/*
Copyright 2022 Google LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha3

import (
	"context"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestValidateCreate(t *testing.T) {
	ctx := context.Background()
	r := FQDNNetworkPolicy{}
	if _, err := r.GetValidResource().ValidateCreate(ctx, &r); err != nil {
		t.Error("Valid resource marked as invalid during creation")
	}

	if _, err := r.GetValidIngressResource().ValidateCreate(ctx, &r); err != nil {
		t.Error("Valid resource with Ingress policy marked as invalid during creation")
	}

	if _, err := r.GetValidNoPortResource().ValidateCreate(ctx, &r); err != nil {
		t.Error("Valid resource with no port marked as invalid during creation")
	}

	if _, err := r.GetValidNoProtocolResource().ValidateCreate(ctx, &r); err != nil {
		t.Error("Valid resource with no protocol marked as invalid during creation")
	}

	if _, err := r.GetInvalidResource().ValidateCreate(ctx, &r); err == nil {
		t.Error("Invalid resource marked as valid during creation")
	}
}

func TestValidateUpdate(t *testing.T) {
	r := FQDNNetworkPolicy{}
	ro := FQDNNetworkPolicy{}
	r.GetValidResource()
	ro.GetInvalidResource()

	if _, err := r.GetValidResource().ValidateUpdate(ctx, &ro, &r); err != nil {
		t.Error("Valid resource marked as invalid during update")
	}

	if _, err := r.GetValidIngressResource().ValidateUpdate(ctx, &ro, &r); err != nil {
		t.Error("Valid resource with Ingress policy marked as invalid during update")
	}

	if _, err := r.GetValidNoPortResource().ValidateUpdate(ctx, &ro, &r); err != nil {
		t.Error("Valid resource with no port marked as invalid during update")
	}

	if _, err := r.GetValidNoProtocolResource().ValidateUpdate(ctx, &ro, &r); err != nil {
		t.Error("Valid resource with no protocol marked as invalid during update")
	}

	ro.GetValidResource()
	if _, err := r.GetInvalidResource().ValidateUpdate(ctx, &ro, &r); err == nil {
		t.Error("Invalid resource marked as valid during update")
	}
}

func TestValidateDelete(t *testing.T) {
	r := FQDNNetworkPolicy{}

	if _, err := r.GetValidResource().ValidateDelete(ctx, &r); err != nil {
		t.Error("Valid resource marked as invalid during deletion")
	}

	if _, err := r.GetValidIngressResource().ValidateDelete(ctx, &r); err != nil {
		t.Error("Valid resource with Ingress policy marked as invalid during deletion")
	}

	if _, err := r.GetValidNoPortResource().ValidateDelete(ctx, &r); err != nil {
		t.Error("Valid resource with no port marked as invalid during deletion")
	}

	if _, err := r.GetValidNoProtocolResource().ValidateDelete(ctx, &r); err != nil {
		t.Error("Valid resource with no protocol marked as invalid during deletion")
	}

	r.GetInvalidResource()
	if _, err := r.ValidateDelete(ctx, &r); err != nil {
		t.Error("Impossible to delete invalid resource")
	}
}

func TestValidatePorts(t *testing.T) {
	r := FQDNNetworkPolicy{}

	if r.GetValidResource().ValidatePorts() != nil {
		t.Error("Valid resource marked as having invalid ports")
	}
	if r.GetValidIngressResource().ValidatePorts() != nil {
		t.Error("Valid resource with Ingress policy marked as having invalid ports")
	}
	if r.GetValidNoPortResource().ValidatePorts() != nil {
		t.Error("Valid resource with no port marked as having invalid ports")
	}
	if r.GetValidNoProtocolResource().ValidatePorts() != nil {
		t.Error("Valid resource with no protocol marked as having invalid ports")
	}

	r.LoadResource("./config/samples/networking_v1alpha3_fqdnnetworkpolicy_invalid_port.yaml")
	if r.ValidatePorts() == nil {
		t.Error("Resource with invalid ports marked as valid")
	}
	r.LoadResource("./config/samples/networking_v1alpha3_fqdnnetworkpolicy_invalid_protocol.yaml")
	if r.ValidatePorts() == nil {
		t.Error("Resource with invalid protocol marked as valid")
	}
}

func TestDefault(t *testing.T) {
	policy := &FQDNNetworkPolicy{
		Spec: FQDNNetworkPolicySpec{
			Egress: []FQDNNetworkPolicyEgressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocolPointer("")}},
			}},
			Ingress: []FQDNNetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocolPointer("")}},
			}},
		},
	}

	if err := policy.Default(context.Background(), policy); err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	if got := *policy.Spec.Egress[0].Ports[0].Protocol; got != v1.ProtocolTCP {
		t.Errorf("egress protocol = %q, want %q", got, v1.ProtocolTCP)
	}
	if got := *policy.Spec.Ingress[0].Ports[0].Protocol; got != v1.ProtocolTCP {
		t.Errorf("ingress protocol = %q, want %q", got, v1.ProtocolTCP)
	}

	policy.Spec.Egress[0].Ports[0].Protocol = protocolPointer(v1.ProtocolUDP)
	policy.Spec.Ingress[0].Ports = nil
	if err := policy.Default(context.Background(), policy); err != nil {
		t.Fatalf("Default() with configured protocol and nil ports error = %v", err)
	}
	if got := *policy.Spec.Egress[0].Ports[0].Protocol; got != v1.ProtocolUDP {
		t.Errorf("configured egress protocol changed to %q", got)
	}
}

func TestValidatePortsOutOfRangeIngressAndEgress(t *testing.T) {
	protocol := v1.ProtocolTCP
	egressPort := intstr.FromInt32(65536)
	ingressPort := intstr.FromInt32(-1)
	policy := &FQDNNetworkPolicy{
		Spec: FQDNNetworkPolicySpec{
			Egress: []FQDNNetworkPolicyEgressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{
					Port:     &egressPort,
					Protocol: &protocol,
				}},
			}},
			Ingress: []FQDNNetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{
					Port:     &ingressPort,
					Protocol: &protocol,
				}},
			}},
		},
	}

	if errs := policy.ValidatePorts(); len(errs) != 2 {
		t.Fatalf("ValidatePorts() returned %d errors, want 2: %v", len(errs), errs)
	}
}

func protocolPointer(protocol v1.Protocol) *v1.Protocol {
	return &protocol
}

func TestValidateFQDNs(t *testing.T) {
	r := FQDNNetworkPolicy{}

	if r.GetValidResource().ValidateFQDNs() != nil {
		t.Error("Valid resource marked as having invalid FQDNs")
	}
	if r.GetValidIngressResource().ValidateFQDNs() != nil {
		t.Error("Valid resource with Ingress policy marked as having invalid FQDNs")
	}
	if r.GetValidNoPortResource().ValidatePorts() != nil {
		t.Error("Valid resource with no port marked as having invalid ports")
	}
	if r.GetValidNoProtocolResource().ValidatePorts() != nil {
		t.Error("Valid resource with no protocol marked as having invalid ports")
	}

	r.LoadResource("./config/samples/networking_v1alpha3_fqdnnetworkpolicy_invalid_wildcard.yaml")
	if r.ValidateFQDNs() == nil {
		t.Error("Resource with wildcard marked as valid")
	}
	r.LoadResource("./config/samples/networking_v1alpha3_fqdnnetworkpolicy_invalid_fqdntoolong.yaml")
	if r.ValidateFQDNs() == nil {
		t.Error("Resource with invalid FQDN (too long) marked as valid")
	}
	r.LoadResource("./config/samples/networking_v1alpha3_fqdnnetworkpolicy_invalid_labeltoolong.yaml")
	if r.ValidateFQDNs() == nil {
		t.Error("Resource with invalid FQDN (label too long) marked as valid")
	}
}
