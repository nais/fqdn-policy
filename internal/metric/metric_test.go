package metrics

import (
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestMetricsRegisteredAndIncremented(t *testing.T) {
	DNSResolveCounter.WithLabelValues("fresh", "metric-test.example", "A").Inc()
	NetworkPolicyResultCounter.WithLabelValues("success").Inc()

	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	got := make(map[string]float64)
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if family.GetName() == "domain_lookup_count" || family.GetName() == "network_policy_apply_result_count" {
				got[family.GetName()] += metric.GetCounter().GetValue()
			}
		}
	}

	if got["domain_lookup_count"] < 1 {
		t.Errorf("domain_lookup_count = %v, want at least 1", got["domain_lookup_count"])
	}
	if got["network_policy_apply_result_count"] < 1 {
		t.Errorf("network_policy_apply_result_count = %v, want at least 1", got["network_policy_apply_result_count"])
	}
}
