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

	"github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang/api/v1alpha3"
	"github.com/miekg/dns"
	"github.com/sourcegraph/conc/pool"
	networking "k8s.io/api/networking/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisterv1 "k8s.io/client-go/listers/core/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

type (
	Client struct {
		*dns.Client
		cfg            *dns.ClientConfig
		endpointLister corelisterv1.EndpointsLister
		lock           sync.RWMutex
		domainCache    map[string]Records
	}

	Record struct {
		IP        net.IP
		ExpiresAt time.Time
	}

	Conns   []*dns.Conn
	Records []Record
)

func NewClient(ctx context.Context, k8sclient kubernetes.Interface) (*Client, error) {
	c := new(dns.Client)

	var lister corelisterv1.EndpointsLister
	if isKubernetes() {
		inf := informers.NewSharedInformerFactoryWithOptions(
			k8sclient,
			20*time.Minute,
			informers.WithNamespace("kube-system"),
		)
		lister = inf.Core().V1().Endpoints().Lister()
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
		cfg:            dnscfg,
		endpointLister: lister,
		domainCache:    make(map[string]Records),
	}, nil
}

func (c *Client) Connections(ctx context.Context) (Conns, error) {
	conns := make(Conns, 0)
	cfg := c.cfg

	if isKubernetes() {
		// Re-fetch the kube-dns service endpoints on every call to Connections
		kcfg, err := c.kubernetesConfig()
		if err != nil {
			return nil, fmt.Errorf("resolving kube-dns service endpoints; continuing with default configuration: %w", err)
		}
		cfg = kcfg
	}

	for _, nameserver := range cfg.Servers {
		conn, err := c.DialContext(ctx, nameserver+":"+cfg.Port)
		if err != nil {
			return conns, fmt.Errorf("dialing %s: %w", nameserver, err)
		}
		conns = append(conns, conn)
	}

	return conns, nil
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

func (c *Client) storeRecordsInCache(fqdn string, records Records) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.domainCache[fqdn] = records
}

func (c *Client) getRecordsFromCache(fqdn string) (Records, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	records, ok := c.domainCache[fqdn]
	return records, ok
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

	cachedRecords, ok := c.getRecordsFromCache(fqdn)
	if ok && !cachedRecords.HasExpired() {
		return cachedRecords, nil
	}

	conns, err := c.Connections(ctx)
	defer func() {
		if conns != nil {
			_ = conns.Close()
		}
	}()
	if err != nil {
		return nil, err
	}

	eg := pool.NewWithResults[Records]().WithContext(ctx).WithCancelOnError()
	for _, conn := range conns {
		eg.Go(func(ctx context.Context) (Records, error) {
			err := conn.WriteMsg(m)
			if err != nil {
				return nil, fmt.Errorf("writing message: %w", err)
			}

			r, err := conn.ReadMsg()
			if err != nil {
				return nil, fmt.Errorf("reading message: %w", err)
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
	for _, r := range cachedRecords {
		if r.ExpiresAt.Before(time.Now()) {
			continue
		}

		contains := slices.ContainsFunc(all, func(a Record) bool {
			return a.IP.Equal(r.IP)
		})
		if contains {
			continue
		}

		all = append(all, r)
	}

	c.storeRecordsInCache(fqdn, all)

	return all, nil
}

func (c *Client) kubernetesConfig() (*dns.ClientConfig, error) {
	cfg := &dns.ClientConfig{
		// Servers:  c.cfg.Servers[:],
		Port:     c.cfg.Port,
		Search:   c.cfg.Search[:],
		Ndots:    c.cfg.Ndots,
		Timeout:  c.cfg.Timeout,
		Attempts: c.cfg.Attempts,
	}

	ep, err := c.endpointLister.Endpoints("kube-system").Get("kube-dns")
	if err != nil {
		return cfg, fmt.Errorf("fetching kube-dns service endpoints: %w", err)
	}

	for _, subset := range ep.Subsets {
		for _, addr := range subset.Addresses {
			cfg.Servers = append(cfg.Servers, addr.IP)
		}
	}
	return cfg, nil
}

func (r *Record) cidr() string {
	if len(r.IP) == net.IPv4len {
		return "/32"
	}

	return "/128"
}

func (r Records) AsNetworkPolicyPeers() []networking.NetworkPolicyPeer {
	peers := make([]networking.NetworkPolicyPeer, 0)
	for _, record := range r {
		peers = append(peers, networking.NetworkPolicyPeer{
			IPBlock: &networking.IPBlock{
				CIDR: record.IP.String() + record.cidr(),
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
	for _, record := range r {
		if time.Now().After(record.ExpiresAt) {
			return true
		}
	}
	return false
}

func (c Conns) Close() error {
	eg := pool.New().WithErrors()
	for _, conn := range c {
		eg.Go(func() error {
			return conn.Close()
		})
	}
	return eg.Wait()
}

func isKubernetes() bool {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	return len(host) > 0 && len(port) > 0
}
