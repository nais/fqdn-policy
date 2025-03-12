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

package controllers

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"
	networkingv1alpha3 "github.com/nais/fqdn-policy/api/v1alpha3"
	"github.com/nais/fqdn-policy/internal/dns"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// FQDNNetworkPolicyReconciler reconciles a FQDNNetworkPolicy object
type FQDNNetworkPolicyReconciler struct {
	client.Client
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Config    Config
	DNSClient *dns.Client
}

type Config struct {
	SkipAAAA       bool
	NextSyncPeriod int
}

var (
	aaaaLookupsAnnotation = "fqdnnetworkpolicies.networking.gke.io/aaaa-lookups"
	// finalizerName is kept for legacy purposes.
	// It shouldn't be used other than for removal from existing FQDNNetworkPolicy resources.
	finalizerName = "finalizer.fqdnnetworkpolicies.networking.gke.io"
)

// +kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies/status,verbs=get;update;patch

func (r *FQDNNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", req.NamespacedName)
	ctrllog.IntoContext(ctx, log)

	fqdnNetworkPolicy := &networkingv1alpha3.FQDNNetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Name,
	}, fqdnNetworkPolicy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch FQDNNetworkPolicy")
		return ctrl.Result{}, err
	}

	// Check and remove finalizer from legacy resources that still have them
	if controllerutil.ContainsFinalizer(fqdnNetworkPolicy, finalizerName) {
		controllerutil.RemoveFinalizer(fqdnNetworkPolicy, finalizerName)
		if err := r.Update(ctx, fqdnNetworkPolicy); err != nil {
			return ctrl.Result{}, err
		}
	}

	if !fqdnNetworkPolicy.GetObjectMeta().GetDeletionTimestamp().IsZero() {
		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	result, err := r.createOrUpdateNetworkPolicy(ctx, fqdnNetworkPolicy)
	if err != nil {
		log.Error(err, "unable to create or update NetworkPolicy")
		fqdnNetworkPolicy.Status.State = networkingv1alpha3.PendingState
		fqdnNetworkPolicy.Status.Reason = err.Error()

		if e := r.Status().Update(ctx, fqdnNetworkPolicy); e != nil {
			log.Error(e, "unable to update FQDNNetworkPolicy status")
			return ctrl.Result{}, e
		}

		return ctrl.Result{}, err
	}

	// Need to fetch the object again before updating it
	// as its status may have changed since the first time
	// we fetched it.
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Name,
	}, fqdnNetworkPolicy); err != nil {
		log.Error(err, "unable to fetch FQDNNetworkPolicy")
		return ctrl.Result{}, err
	}

	if fqdnNetworkPolicy.Status.State != networkingv1alpha3.ActiveState || fqdnNetworkPolicy.Status.NextSyncTime != nil {
		fqdnNetworkPolicy.Status.State = networkingv1alpha3.ActiveState
		fqdnNetworkPolicy.Status.Reason = ""
		fqdnNetworkPolicy.Status.NextSyncTime = nil

		if err := r.Status().Update(ctx, fqdnNetworkPolicy); err != nil {
			log.Error(err, "unable to update FQDNNetworkPolicy status")
			return ctrl.Result{}, err
		}
	}

	return result, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FQDNNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mgr.GetFieldIndexer()
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha3.FQDNNetworkPolicy{}).
		WithEventFilter(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		)).
		Complete(r)
}

func (r *FQDNNetworkPolicyReconciler) createOrUpdateNetworkPolicy(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	// Trying to fetch an existing NetworkPolicy of the same name as our FQDNNetworkPolicy
	networkPolicy := &networking.NetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: fqdnNetworkPolicy.Namespace,
		Name:      fqdnNetworkPolicy.Name,
	}, networkPolicy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// If there is none, that's OK, it means that we just haven't created it yet
			log.V(1).Info("associated NetworkPolicy doesn't exist, creating it")
		} else {
			return ctrl.Result{}, err
		}
	} else {
		log.V(2).Info("Found NetworkPolicy")
	}

	egressRules, nextSync, err := r.getNetworkPolicyEgressRules(ctx, fqdnNetworkPolicy)
	if err != nil {
		return ctrl.Result{}, err
	}

	policyTypes := fqdnNetworkPolicy.Spec.PolicyTypes

	// Prevent provisioning a policy that inadvertently blocks all egress traffic.
	if len(egressRules) == 0 && slices.Contains(policyTypes, networking.PolicyTypeEgress) {
		log.Info("No egress rules resolved, removing egress policy type")
		policyTypes = slices.DeleteFunc(policyTypes, func(t networking.PolicyType) bool {
			return t == networking.PolicyTypeEgress
		})
	}

	ingressRules, ingressNextSync, err := r.getNetworkPolicyIngressRules(ctx, fqdnNetworkPolicy)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Prevent provisioning a policy that inadvertently blocks all ingress traffic.
	if len(ingressRules) == 0 && slices.Contains(policyTypes, networking.PolicyTypeIngress) {
		log.Info("No ingress rules resolved, removing ingress policy type")
		policyTypes = slices.DeleteFunc(policyTypes, func(t networking.PolicyType) bool {
			return t == networking.PolicyTypeIngress
		})
	}

	// We sync just after the shortest TTL between ingress and egress rules
	if ingressNextSync.Milliseconds() < nextSync.Milliseconds() {
		nextSync = ingressNextSync
	}

	networkPolicy.ObjectMeta.Name = fqdnNetworkPolicy.Name
	networkPolicy.ObjectMeta.Namespace = fqdnNetworkPolicy.Namespace

	res, err := controllerutil.CreateOrUpdate(ctx, r.Client, networkPolicy, func() error {
		if networkPolicy.Annotations == nil {
			networkPolicy.Annotations = make(map[string]string)
		}
		networkPolicy.Spec.PodSelector = fqdnNetworkPolicy.Spec.PodSelector
		networkPolicy.Spec.PolicyTypes = policyTypes
		networkPolicy.Spec.Egress = egressRules
		networkPolicy.Spec.Ingress = ingressRules
		return controllerutil.SetControllerReference(fqdnNetworkPolicy, networkPolicy, r.Scheme)
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	log.Info(fmt.Sprintf("NetworkPolicy %s, next sync in %s", res, nextSync))
	return ctrl.Result{RequeueAfter: *nextSync}, nil
}

// getNetworkPolicyIngressRules returns a slice of NetworkPolicyIngressRules based on the
// provided slice of FQDNNetworkPolicyIngressRules, also returns when the next sync should happen
// based on the TTL of records
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyIngressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) ([]networking.NetworkPolicyIngressRule, *time.Duration, error) {
	log := ctrllog.FromContext(ctx)

	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	nextSync = uint32(r.Config.NextSyncPeriod)

	skipAAAA := fqdnNetworkPolicy.Annotations[aaaaLookupsAnnotation] == "skip" || r.Config.SkipAAAA
	if skipAAAA {
		log.V(1).Info("FQDNNetworkPolicy has AAAA lookups policy set to skip, not resolving AAAA records")
	}

	rules := make([]networking.NetworkPolicyIngressRule, 0)
	for _, rule := range fqdnNetworkPolicy.Spec.Ingress {
		records, err := r.DNSClient.ResolveFQDNs(ctx, rule.From, skipAAAA)
		if err != nil {
			return nil, nil, err
		}

		if len(records) == 0 {
			log.V(1).Info("No resolved records, skipping ingress rule.")
			continue
		}

		rules = append(rules, networking.NetworkPolicyIngressRule{
			Ports: rule.Ports,
			From:  records.AsNetworkPolicyPeers(),
		})

		if ttl, ok := records.LowestTTL(); ok && ttl < nextSync {
			nextSync = ttl
		}
	}

	n := time.Second * time.Duration(nextSync)

	return rules, &n, nil
}

// getNetworkPolicyEgressRules returns a slice of NetworkPolicyEgressRules based on the
// provided slice of FQDNNetworkPolicyEgressRules, also returns when the next sync should happen
// based on the TTL of records
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyEgressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) ([]networking.NetworkPolicyEgressRule, *time.Duration, error) {
	log := ctrllog.FromContext(ctx)

	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	nextSync = uint32(r.Config.NextSyncPeriod)

	skipAAAA := fqdnNetworkPolicy.Annotations[aaaaLookupsAnnotation] == "skip" || r.Config.SkipAAAA
	if skipAAAA {
		log.V(1).Info("FQDNNetworkPolicy has AAAA lookups policy set to skip, not resolving AAAA records")
	}

	rules := make([]networking.NetworkPolicyEgressRule, 0)
	for _, rule := range fqdnNetworkPolicy.Spec.Egress {
		records, err := r.DNSClient.ResolveFQDNs(ctx, rule.To, skipAAAA)
		if err != nil {
			return nil, nil, err
		}

		if len(records) == 0 {
			log.V(1).Info("No resolved records, skipping egress rule.")
			continue
		}

		rules = append(rules, networking.NetworkPolicyEgressRule{
			Ports: rule.Ports,
			To:    records.AsNetworkPolicyPeers(),
		})

		if ttl, ok := records.LowestTTL(); ok && ttl < nextSync {
			nextSync = ttl
		}
	}

	n := time.Second * time.Duration(nextSync)

	return rules, &n, nil
}
