package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	mdns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
	networkingv1alpha3 "github.com/nais/fqdn-policy/api/v1alpha3"
)

func TestResolveFQDNsQueriesServersConcurrently(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	cancel, address := startDNSServer(t, "127.0.0.1:0", "192.0.2.1")
	defer cancel()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	client.defaultCfg = &dnsconf.Config{Servers: []string{"127.0.0.1", "127.0.0.1"}, Port: port}

	for i := range 20 {
		fqdn := fmt.Sprintf("%d.example.test", i)
		records, err := client.ResolveFQDNs(context.Background(), []networkingv1alpha3.FQDNNetworkPolicyPeer{{FQDNs: []string{fqdn}}}, true)
		if err != nil {
			t.Fatal(err)
		}

		if len(records) != 2 {
			t.Fatalf("expected two records, got %d", len(records))
		}
		addresses := []string{records[0].IP.String(), records[1].IP.String()}
		slices.Sort(addresses)
		if !slices.Equal(addresses, []string{"192.0.2.1", "192.0.2.1"}) {
			t.Fatalf("unexpected addresses: %v", addresses)
		}
	}
}

func TestRecordsHelpers(t *testing.T) {
	t.Run("empty records", func(t *testing.T) {
		var records Records
		if ttl, ok := records.LowestTTL(); ok || ttl != 0 {
			t.Fatalf("LowestTTL() = (%d, %t), want (0, false)", ttl, ok)
		}
		if !records.HasExpired() {
			t.Fatal("HasExpired() = false, want true for empty records")
		}
		if peers := records.AsNetworkPolicyPeers(); len(peers) != 0 {
			t.Fatalf("AsNetworkPolicyPeers() returned %d peers, want 0", len(peers))
		}
	})

	t.Run("valid records", func(t *testing.T) {
		expiresAt := time.Now().Add(20 * time.Second)
		records := Records{
			{IP: net.IP{192, 0, 2, 1}, ExpiresAt: expiresAt.Add(time.Minute)},
			{IP: net.ParseIP("2001:db8::1"), ExpiresAt: expiresAt},
			{IP: net.IP{192, 0, 2, 1}, ExpiresAt: expiresAt},
		}

		ttl, ok := records.LowestTTL()
		if !ok || ttl < 18 || ttl > 20 {
			t.Fatalf("LowestTTL() = (%d, %t), want a TTL close to 20 seconds", ttl, ok)
		}
		if records.HasExpired() {
			t.Fatal("HasExpired() = true, want false for unexpired records")
		}

		peers := records.AsNetworkPolicyPeers()
		if len(peers) != 2 {
			t.Fatalf("AsNetworkPolicyPeers() returned %d peers, want 2 after deduplication", len(peers))
		}
		got := []string{peers[0].IPBlock.CIDR, peers[1].IPBlock.CIDR}
		want := []string{"192.0.2.1/32", "2001:db8::1/128"}
		if !slices.Equal(got, want) {
			t.Fatalf("AsNetworkPolicyPeers() CIDRs = %v, want %v", got, want)
		}
	})

	t.Run("expired record", func(t *testing.T) {
		records := Records{{IP: net.IP{192, 0, 2, 1}, ExpiresAt: time.Now().Add(-time.Second)}}
		if !records.HasExpired() {
			t.Fatal("HasExpired() = false, want true for expired records")
		}
	})
}

func startDNSServer(t *testing.T, address, responseIP string) (func(), string) {
	t.Helper()

	handler := mdns.HandlerFunc(func(_ context.Context, w mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		dnsutil.SetReply(response, request)
		response.Answer = []mdns.RR{&mdns.A{
			Hdr:  mdns.Header{Name: request.Question[0].Header().Name, TTL: 60, Class: mdns.ClassINET},
			Addr: netip.MustParseAddr(responseIP),
		}}
		_, _ = io.Copy(w, response)
	})

	cancel, listening, err := dnstest.UDPServer(address, func(server *mdns.Server) {
		server.Handler = handler
	})
	if err != nil {
		t.Fatal(err)
	}
	return cancel, listening
}
