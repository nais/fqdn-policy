package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	DNSResolveCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "domain_lookup_count",
			Help: "Number of DNS lookups performed",
		},
		[]string{"source", "domain", "record_type"},
	)
	NetworkPolicyResultCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_policy_apply_result_count",
			Help: "Number of network policies applied",
		},
		[]string{"result"},
	)
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(DNSResolveCounter)
}
