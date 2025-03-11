package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var DNSResolveCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "domain_lookup_count",
		Help: "Number of DNS lookups performed",
	},
	[]string{"source", "domain", "record_type"},
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(DNSResolveCounter)
}
