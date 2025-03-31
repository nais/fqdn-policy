package dns

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nais/fqdn-policy/api/v1alpha3"
	metrics "github.com/nais/fqdn-policy/internal/metric"
	"github.com/sourcegraph/conc/pool"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	discoverylisterv1 "k8s.io/client-go/listers/discovery/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

type (
	Client struct {
		*dns.Client
		defaultCfg     *dns.ClientConfig
		endpointLister discoverylisterv1.EndpointSliceLister
		lock           sync.RWMutex
		domainCache    map[string]Records
	}

	Record struct {
		IP        net.IP
		ExpiresAt time.Time
	}

	Records []Record
)

func NewClient(ctx context.Context, k8sclient kubernetes.Interface) (*Client, error) {
	c := new(dns.Client)

	var lister discoverylisterv1.EndpointSliceLister
	if isKubernetes() {
		inf := informers.NewSharedInformerFactoryWithOptions(
			k8sclient,
			20*time.Minute,
			informers.WithNamespace("kube-system"),
		)
		lister = inf.Discovery().V1().EndpointSlices().Lister()
		inf.Start(ctx.Done())
		waitCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()

		done := inf.WaitForCacheSync(waitCtx.Done())
		for _, ok := range done {
			if !ok {
				return nil, fmt.Errorf("timed out waiting for caches to sync")
			}
		}
	}

	dnscfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("parsing /etc/resolv.conf: %w", err)
	}

	return &Client{
		Client:         c,
		defaultCfg:     dnscfg,
		endpointLister: lister,
		domainCache:    make(map[string]Records),
	}, nil
}

func (c *Client) ResolveFQDNs(ctx context.Context, peers []v1alpha3.FQDNNetworkPolicyPeer, skipAAAA bool) (Records, error) {
	records := make(Records, 0)

	for _, peer := range peers {
		for _, fqdn := range peer.FQDNs {
			aRecords, err := c.resolve(ctx, fqdn, dns.TypeA)
			if err != nil {
				return nil, err
			}
			records = slices.Concat(records, aRecords)

			if skipAAAA {
				continue
			}
			aaaaRecords, err := c.resolve(ctx, fqdn, dns.TypeAAAA)
			if err != nil {
				return nil, err
			}
			records = slices.Concat(records, aaaaRecords)
		}
	}

	return records, nil
}

func (c *Client) dnsAddresses(ctx context.Context) ([]string, error) {
	ips := c.defaultCfg.Servers
	port := c.defaultCfg.Port

	if isKubernetes() {
		var err error
		ips, err = c.kubeDNSIPs(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolving kube-dns service endpoints; continuing with default configuration: %w", err)
		}
		port = "53"
	}

	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip+":"+port)
	}
	return addrs, nil
}

func (c *Client) kubeDNSIPs(ctx context.Context) ([]string, error) {
	selector := labels.Set{
		"k8s-app": "kube-dns",
	}.AsSelector()
	epSlices, err := c.endpointLister.
		EndpointSlices("kube-system").
		List(selector)
	if err != nil {
		return nil, fmt.Errorf("fetching kube-dns service endpoints: %w", err)
	}

	servers := make([]string, 0)

	for _, epSlice := range epSlices {
		for _, ep := range epSlice.Endpoints {
			if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
				continue
			}
			if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
				continue
			}
			servers = append(servers, ep.Addresses...)
		}
	}
	if len(servers) == 0 {
		ctrllog.FromContext(ctx).V(1).Info("no kube-dns service endpoints found; using default DNS configuration")
	}

	return servers, nil
}

func (c *Client) getRecordsFromCache(fqdn, recordType string) (Records, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	records, ok := c.domainCache[fqdn+":"+recordType]
	return records, ok
}

func (c *Client) storeRecordsInCache(fqdn, recordType string, records Records) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.domainCache[fqdn+":"+recordType] = records
}

func (c *Client) resolve(ctx context.Context, fqdn string, questionType uint16) (Records, error) {
	log := ctrllog.FromContext(ctx)
	f := dns.Fqdn(fqdn)
	m := new(dns.Msg)
	m.SetQuestion(f, questionType)

	recordType := "A"
	if questionType == dns.TypeAAAA {
		recordType = "AAAA"
	}

	cachedRecords, ok := c.getRecordsFromCache(fqdn, recordType)
	if ok && !cachedRecords.HasExpired() {
		metrics.DNSResolveCounter.WithLabelValues("cached", fqdn, recordType).Inc()
		return cachedRecords, nil
	}

	// Re-fetch the kube-dns service endpoints
	addrs, err := c.dnsAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolving DNS addresses: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	eg := pool.NewWithResults[Records]().WithContext(ctx).WithCancelOnError()
	for _, addr := range addrs {
		eg.Go(func(ctx context.Context) (Records, error) {
			r, _, err := c.ExchangeContext(ctx, m, addr)
			if err != nil {
				return nil, err
			}

			if len(r.Answer) == 0 {
				log.V(1).Info("could not find " + recordType + " record for " + f)
			}

			records := make(Records, 0)
			for _, ans := range r.Answer {
				expiresAt := time.Now().Add(time.Second * time.Duration(ans.Header().Ttl))
				switch t := ans.(type) {
				case *dns.A:
					records = append(records, Record{
						IP:        t.A,
						ExpiresAt: expiresAt,
					})
				case *dns.AAAA:
					records = append(records, Record{
						IP:        t.AAAA,
						ExpiresAt: expiresAt,
					})
				}
			}

			return records, nil
		})
	}

	liveRecords, err := eg.Wait()
	if err != nil {
		return nil, fmt.Errorf("resolving %s record for %s: %w", recordType, f, err)
	}

	all := slices.Concat(liveRecords...)

	// Inject cached records into the result to allow a grace period for applications with cached DNS records
	source := "fresh"
	for _, r := range cachedRecords {
		isStale := time.Since(r.ExpiresAt) > 5*time.Minute
		if isStale {
			// Skip expired records
			continue
		}

		contains := slices.ContainsFunc(all, func(a Record) bool {
			return a.IP.Equal(r.IP)
		})
		if contains {
			// Skip duplicates
			continue
		}

		source = "combined"
		all = append(all, r)
	}

	metrics.DNSResolveCounter.WithLabelValues(source, fqdn, recordType).Inc()

	c.storeRecordsInCache(fqdn, recordType, all)

	return all, nil
}

func (r *Record) toCIDR() string {
	if len(r.IP) == net.IPv4len {
		return r.IP.String() + "/32"
	}

	return r.IP.String() + "/128"
}

func (r Records) AsNetworkPolicyPeers() []networking.NetworkPolicyPeer {
	peers := make([]networking.NetworkPolicyPeer, 0, len(r))
	for _, record := range r {
		peers = append(peers, networking.NetworkPolicyPeer{
			IPBlock: &networking.IPBlock{
				CIDR: record.toCIDR(),
			},
		})
	}

	// Sort peers for stability
	slices.SortFunc(peers, func(a, b networking.NetworkPolicyPeer) int {
		return cmp.Compare(a.IPBlock.CIDR, b.IPBlock.CIDR)
	})

	// Deduplicate peers
	peers = slices.CompactFunc(peers, func(a, b networking.NetworkPolicyPeer) bool {
		return a.IPBlock.CIDR == b.IPBlock.CIDR
	})

	return peers
}

func (r Records) LowestTTL() (uint32, bool) {
	if len(r) == 0 {
		return 0, false
	}

	lowest := r[0].ExpiresAt
	for _, record := range r {
		if record.ExpiresAt.Before(lowest) {
			lowest = record.ExpiresAt
		}
	}

	return uint32(time.Until(lowest).Seconds()), true
}

func (r Records) HasExpired() bool {
	if len(r) == 0 {
		return true
	}
	for _, record := range r {
		if time.Now().After(record.ExpiresAt) {
			return true
		}
	}
	return false
}

func isKubernetes() bool {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	return len(host) > 0 && len(port) > 0
}
