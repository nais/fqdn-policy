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
	"fmt"

	"golang.org/x/net/idna"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var fqdnnetworkpolicylog = logf.Log.WithName("fqdnnetworkpolicy-resource")

func (r *FQDNNetworkPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(r).
		WithValidator(r).
		Complete()
}

var _ webhook.CustomDefaulter = &FQDNNetworkPolicy{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *FQDNNetworkPolicy) Default(ctx context.Context, obj runtime.Object) error {
	policy, ok := obj.(*FQDNNetworkPolicy)
	if !ok {
		return fmt.Errorf("expected an FQDNNetworkPolicy but got a %T", obj)
	}

	fqdnnetworkpolicylog.Info("default", "name", policy.Name)

	for ie, rule := range policy.Spec.Egress {
		if rule.Ports != nil {
			for ip, port := range rule.Ports {
				if *port.Protocol == "" {
					fqdnnetworkpolicylog.V(1).Info("No protocol set, defaulting to TCP",
						"namespace", policy.ObjectMeta.Namespace,
						"name", policy.ObjectMeta.Name,
						"path", field.NewPath("spec").Child("egress").
							Index(ie).Child("ports").Index(ip).String())
					*port.Protocol = v1.ProtocolTCP
				}
			}
		}
	}
	for ii, rule := range policy.Spec.Ingress {
		if rule.Ports != nil {
			for ip, port := range rule.Ports {
				if *port.Protocol == "" {
					fqdnnetworkpolicylog.V(1).Info("No protocol set, defaulting to TCP",
						"namespace", policy.ObjectMeta.Namespace,
						"name", policy.ObjectMeta.Name,
						"path", field.NewPath("spec").Child("ingress").
							Index(ii).Child("ports").Index(ip).String())
					*port.Protocol = v1.ProtocolTCP
				}
			}
		}
	}

	return nil
}

var _ webhook.CustomValidator = &FQDNNetworkPolicy{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *FQDNNetworkPolicy) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*FQDNNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an FQDNNetworkPolicy but got a %T", obj)
	}
	fqdnnetworkpolicylog.Info("validate create", "name", policy.Name)

	var allErrs field.ErrorList
	allErrs = append(allErrs, policy.ValidatePorts()...)
	allErrs = append(allErrs, policy.ValidateFQDNs()...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(
		schema.GroupKind{Group: "networking.gke.io", Kind: "FQDNNetworkPolicy"},
		r.Name, allErrs)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *FQDNNetworkPolicy) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	policy, ok := newObj.(*FQDNNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an FQDNNetworkPolicy but got a %T", newObj)
	}
	fqdnnetworkpolicylog.Info("validate update", "name", policy.Name)

	var allErrs field.ErrorList
	allErrs = append(allErrs, policy.ValidatePorts()...)
	allErrs = append(allErrs, policy.ValidateFQDNs()...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(
		schema.GroupKind{Group: "networking.gke.io", Kind: "FQDNNetworkPolicy"},
		r.Name, allErrs)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *FQDNNetworkPolicy) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*FQDNNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an FQDNNetworkPolicy but got a %T", obj)
	}
	fqdnnetworkpolicylog.Info("validate delete", "name", policy.Name)

	return nil, nil
}

// ValidatePorts checks that the FQDNNetworkPolicy only contains valid ports (from 1 to 65535)
func (r *FQDNNetworkPolicy) ValidatePorts() field.ErrorList {
	var allErrs field.ErrorList

	for ie, rule := range r.Spec.Egress {
		if rule.Ports != nil {
			for ip, port := range rule.Ports {
				if port.Port.IntVal < 0 || port.Port.IntVal > 65535 {
					allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("egress").
						Index(ie).Child("ports").Index(ip).Child("port"),
						port.Port, "Invalid port. Must be between 0 and 65535."))
				}
				if port.Port.IntVal == 0 {
					fqdnnetworkpolicylog.Info("port not set or set to 0, will match all ports",
						"name", r.ObjectMeta.Name,
						"namespace", r.ObjectMeta.Namespace,
						"resource", field.NewPath("spec").Child("egress").
							Index(ie).Child("ports").Index(ip).Child("port").String())
				}
				if *port.Protocol != v1.ProtocolTCP && *port.Protocol != v1.ProtocolUDP &&
					*port.Protocol != v1.ProtocolSCTP && *port.Protocol != "" {
					allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("egress").
						Index(ie).Child("ports").Index(ip).Child("protocol"),
						port.Port, "Invalid protocol. Must be TCP, UDP, or SCTP."))
				}
			}
		}
	}
	for ii, rule := range r.Spec.Ingress {
		if rule.Ports != nil {
			for ip, port := range rule.Ports {
				if port.Port.IntVal < 0 || port.Port.IntVal > 65535 {
					allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("ingress").
						Index(ii).Child("ports").Index(ip).Child("port"),
						port.Port, "Invalid port. Must be between 0 and 65535."))
				}
				if port.Port.IntVal == 0 {
					fqdnnetworkpolicylog.Info("port not set or set to 0, will match all ports",
						"name", r.ObjectMeta.Name,
						"namespace", r.ObjectMeta.Namespace,
						"resource", field.NewPath("spec").Child("ingress").
							Index(ii).Child("ports").Index(ip).Child("port").String())
				}
				if *port.Protocol != v1.ProtocolTCP && *port.Protocol != v1.ProtocolUDP &&
					*port.Protocol != v1.ProtocolSCTP && *port.Protocol != "" {
					allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("ingress").
						Index(ii).Child("ports").Index(ip).Child("protocol"),
						port.Port, "Invalid protocol. Must be TCP, UDP, or SCTP."))
				}
			}
		}
	}
	if len(allErrs) == 0 {
		return nil
	}
	return allErrs
}

// ValidateFQDNs checks that the FQDNs provided don't contain any wildcards
func (r *FQDNNetworkPolicy) ValidateFQDNs() field.ErrorList {
	var allErrs field.ErrorList

	for ie, rule := range r.Spec.Egress {
		if rule.To != nil {
			for ito, to := range rule.To {
				for ifqdn, fqdn := range to.FQDNs {
					p := idna.New(idna.ValidateForRegistration())
					_, err := p.ToASCII(fqdn)
					if err != nil {
						allErrs = append(allErrs, field.Invalid(
							field.NewPath("spec").Child("egress").Index(ie).
								Child("to").Index(ito).Child("fqdns").Index(ifqdn),
							fqdn, err.Error()))
					}
				}
			}
		}
	}
	for ii, rule := range r.Spec.Ingress {
		if rule.From != nil {
			for ifrom, from := range rule.From {
				for ifqdn, fqdn := range from.FQDNs {
					p := idna.New(idna.ValidateForRegistration())
					_, err := p.ToASCII(fqdn)
					if err != nil {
						allErrs = append(allErrs, field.Invalid(
							field.NewPath("spec").Child("egress").Index(ii).
								Child("to").Index(ifrom).Child("fqdns").Index(ifqdn),
							fqdn, err.Error()))
					}
				}
			}
		}
	}
	if len(allErrs) == 0 {
		return nil
	}
	return allErrs
}
