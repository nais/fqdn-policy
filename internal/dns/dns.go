package dns

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang/api/v1alpha3"
	"github.com/miekg/dns"
	networking "k8s.io/api/networking/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

type (
	Client struct {
		*dns.Client
		nameservers []string
	}

	Record struct {
		CIDR string
		TTL  uint32
	}

	Records []Record
)

func NewClient() (*Client, error) {
	nameservers, err := Nameservers()
	if err != nil {
		return nil, fmt.Errorf("getting nameservers: %w", err)
	}

	return &Client{
		Client:      new(dns.Client),
		nameservers: nameservers,
	}, nil
}

func Nameservers() ([]string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	nameservers := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, " ")
		if parts[0] != "nameserver" {
			continue
		}

		n := strings.Join(parts[1:], "")
		n = strings.TrimSpace(n)
		nameservers = append(nameservers, n)
	}
	return nameservers, nil
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
	f := fqdn
	// The FQDN in the DNS request needs to end by a dot
	if l := fqdn[len(fqdn)-1]; l != '.' {
		f = fqdn + "."
	}

	m := new(dns.Msg)
	m.SetQuestion(f, questionType)

	recordType := "A"
	if questionType == dns.TypeAAAA {
		recordType = "AAAA"
	}

	// TODO: We're always using the first nameserver. Should we do
	// something different? Note from Jens:
	// by default only if options rotate is set in resolv.conf
	// they are rotated. Otherwise the first is used, after a (5s)
	// timeout the next etc. So this is not too bad for now.
	e, _, err := c.ExchangeContext(ctx, m, "["+c.nameservers[0]+"]:53")
	if err != nil {
		return nil, fmt.Errorf("unable to resolve %s record for %s: %w", recordType, f, err)
	}

	if len(e.Answer) == 0 {
		log := ctrllog.FromContext(ctx)
		log.V(1).Info("could not find " + recordType + " record for " + f)
	}

	records := make(Records, 0)

	for _, ans := range e.Answer {
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

	return records, nil
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
