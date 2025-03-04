package dns

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang/api/v1alpha3"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	networking "k8s.io/api/networking/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

type (
	Client struct {
		*dns.Client
		cfg *dns.ClientConfig
	}

	Config struct {
		KubeServiceName string
		ResolvConfPath  string
	}

	Record struct {
		CIDR string
		TTL  uint32
	}

	Conns   []*dns.Conn
	Records []Record
)

func NewClient(cfg Config) (*Client, error) {
	c := new(dns.Client)

	if len(cfg.KubeServiceName) == 0 {
		cfg.KubeServiceName = "kube-dns"
	}
	if len(cfg.ResolvConfPath) == 0 {
		cfg.ResolvConfPath = "/etc/resolv.conf"
	}

	dnscfg, err := dns.ClientConfigFromFile(cfg.ResolvConfPath)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", cfg.ResolvConfPath, err)
	}

	return &Client{
		Client: c,
		cfg:    dnscfg,
	}, nil
}

func (c *Client) Connections(ctx context.Context) Conns {
	log := ctrllog.FromContext(ctx)
	conns := make(Conns, 0)
	cfg := c.cfg

	if isKubernetes() {
		// Re-fetch the kube-dns service endpoints on every call to Connections
		var err error
		cfg, err = c.kubernetesConfig(ctx)
		if err != nil {
			log.Error(err, "resolving kube-dns service endpoints; continuing with default configuration")
		}
	}

	for _, nameserver := range cfg.Servers {
		conn, err := c.DialContext(ctx, nameserver+":"+cfg.Port)
		if err != nil {
			log.Error(err, "dialing "+nameserver)
			continue
		}
		conns = append(conns, conn)
	}

	return conns
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

func (c *Client) resolve(ctx context.Context, fqdn string, questionType uint16) (Records, error) {
	log := ctrllog.FromContext(ctx)
	f := dns.Fqdn(fqdn)
	m := new(dns.Msg)
	m.SetQuestion(f, questionType)

	recordType := "A"
	if questionType == dns.TypeAAAA {
		recordType = "AAAA"
	}

	conns := c.Connections(ctx)
	defer conns.Close()

	records := make(Records, 0)
	eg := new(errgroup.Group)

	for _, conn := range conns {
		eg.Go(func() error {
			err := conn.WriteMsg(m)
			if err != nil {
				return fmt.Errorf("writing message: %w", err)
			}

			r, err := conn.ReadMsg()
			if err != nil {
				return fmt.Errorf("reading message: %w", err)
			}

			if len(r.Answer) == 0 {
				log.V(1).Info("could not find " + recordType + " record for " + f)
			}

			for _, ans := range r.Answer {
				switch t := ans.(type) {
				case *dns.A:
					records = append(records, Record{
						CIDR: t.A.String() + "/32",
						TTL:  ans.Header().Ttl,
					})
				case *dns.AAAA:
					records = append(records, Record{
						CIDR: t.AAAA.String() + "/128",
						TTL:  ans.Header().Ttl,
					})
				}
			}

			return nil
		})
	}

	err := eg.Wait()
	if err != nil {
		return nil, fmt.Errorf("resolving %s record for %s: %w", recordType, f, err)
	}

	return records, nil
}

func (c *Client) kubernetesConfig(ctx context.Context) (*dns.ClientConfig, error) {
	cfg := c.cfg
	// TODO: resolve pod ips from endpoints for kube-dns service and override cfg.Servers
	// return default cfg if any error occurs
	return cfg, nil
}

func (r Records) AsNetworkPolicyPeers() []networking.NetworkPolicyPeer {
	peers := make([]networking.NetworkPolicyPeer, 0)
	for _, record := range r {
		peers = append(peers, networking.NetworkPolicyPeer{
			IPBlock: &networking.IPBlock{
				CIDR: record.CIDR,
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

	lowest := r[0].TTL
	for _, record := range r {
		if record.TTL < lowest {
			lowest = record.TTL
		}
	}

	return lowest, true
}

func (c Conns) Close() error {
	eg := new(errgroup.Group)
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
