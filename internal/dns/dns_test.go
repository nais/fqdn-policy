package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"

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
