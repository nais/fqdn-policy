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
	"errors"
	"fmt"
	"slices"
	"time"

	networkingv1alpha3 "github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang/api/v1alpha3"
	"github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang/internal/dns"
	"github.com/go-logr/logr"
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
	Log    logr.Logger
	Scheme *runtime.Scheme
	Config Config
}

type Config struct {
	SkipAAAA          bool
	NextSyncPeriod    int
	MinimumSyncPeriod int
}

var (
	ownerAnnotation        = "fqdnnetworkpolicies.networking.gke.io/owned-by"
	deletePolicyAnnotation = "fqdnnetworkpolicies.networking.gke.io/delete-policy"
	aaaaLookupsAnnotation  = "fqdnnetworkpolicies.networking.gke.io/aaaa-lookups"
	finalizerName          = "finalizer.fqdnnetworkpolicies.networking.gke.io"
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

	if fqdnNetworkPolicy.ObjectMeta.DeletionTimestamp.IsZero() {
		// Our FQDNNetworkPolicy is not being deleted
		// If it doesn't already have our finalizer set, we set it
		if !containsString(fqdnNetworkPolicy.GetFinalizers(), finalizerName) {
			fqdnNetworkPolicy.SetFinalizers(append(fqdnNetworkPolicy.GetFinalizers(), finalizerName))
			if err := r.Update(context.Background(), fqdnNetworkPolicy); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// Our FQDNNetworkPolicy is being deleted
		fqdnNetworkPolicy.Status.State = networkingv1alpha3.DestroyingState
		fqdnNetworkPolicy.Status.Reason = "Deleting NetworkPolicy"
		if e := r.Update(ctx, fqdnNetworkPolicy); e != nil {
			log.Error(e, "unable to update FQDNNetworkPolicy status")
			return ctrl.Result{}, e
		}

		if containsString(fqdnNetworkPolicy.GetFinalizers(), finalizerName) {
			// Our finalizer is set, so we need to delete the associated NetworkPolicy
			if err := r.deleteNetworkPolicy(ctx, fqdnNetworkPolicy); err != nil {
				return ctrl.Result{}, err
			}

			// deletion of the NetworkPolicy went well, we remove the finalizer from the list
			fqdnNetworkPolicy.SetFinalizers(removeString(fqdnNetworkPolicy.GetFinalizers(), finalizerName))
			fqdnNetworkPolicy.Status.Reason = "NetworkPolicy deleted or abandonned"
			if err := r.Update(context.Background(), fqdnNetworkPolicy); err != nil {
				return ctrl.Result{}, err
			}
		}

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
	toCreate := false

	// Trying to fetch an existing NetworkPolicy of the same name as our FQDNNetworkPolicy
	networkPolicy := &networking.NetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: fqdnNetworkPolicy.Namespace,
		Name:      fqdnNetworkPolicy.Name,
	}, networkPolicy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// If there is none, that's OK, it means that we just haven't created it yet
			log.V(1).Info("associated NetworkPolicy doesn't exist, creating it")
			toCreate = true
		} else {
			return ctrl.Result{}, err
		}
	}
	if !toCreate {
		log.V(2).Info("Found NetworkPolicy")
	}

	// If we have found a NetworkPolicy, but it doesn't have the right annotation
	// it means that it was created manually beforehand, and we don't want to touch it.
	// This also means that you can have a FQDNNetworkPolicy "adopt" a NetworkPolicy of the
	// same name by adding the correct annotation.
	if !toCreate && networkPolicy.Annotations[ownerAnnotation] != fqdnNetworkPolicy.Name {
		return ctrl.Result{}, errors.New("NetworkPolicy missing owned-by annotation or owned by a different resource")
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
		networkPolicy.Annotations[ownerAnnotation] = fqdnNetworkPolicy.Name
		networkPolicy.Spec.PodSelector = fqdnNetworkPolicy.Spec.PodSelector
		networkPolicy.Spec.PolicyTypes = policyTypes
		networkPolicy.Spec.Egress = egressRules
		networkPolicy.Spec.Ingress = ingressRules
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	log.Info(fmt.Sprintf("NetworkPolicy %s, next sync in %s", res, nextSync))
	return ctrl.Result{RequeueAfter: *nextSync}, nil
}

// deleteNetworkPolicy deletes the NetworkPolicy associated with the fqdnNetworkPolicy FQDNNetworkPolicy
func (r *FQDNNetworkPolicyReconciler) deleteNetworkPolicy(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) error {
	log := ctrllog.FromContext(ctx)

	// Trying to fetch an existing NetworkPolicy of the same name as our FQDNNetworkPolicy
	networkPolicy := &networking.NetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: fqdnNetworkPolicy.Namespace,
		Name:      fqdnNetworkPolicy.Name,
	}, networkPolicy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// If there is none, that's weird, but that's what we want
			log.Info("associated NetworkPolicy doesn't exist")
			return nil
		}
		return err
	}
	if networkPolicy.Annotations[deletePolicyAnnotation] == "abandon" {
		log.Info("NetworkPolicy has delete policy set to abandon, not deleting")
		return nil
	}
	if networkPolicy.Annotations[ownerAnnotation] != fqdnNetworkPolicy.Name {
		log.Info("NetworkPolicy is not owned by FQDNNetworkPolicy, not deleting")
		return nil
	}
	if err := r.Delete(ctx, networkPolicy); err != nil {
		log.Error(err, "unable to delete the NetworkPolicy")
		return err
	}
	log.Info("NetworkPolicy deleted")
	return nil
}

// getNetworkPolicyIngressRules returns a slice of NetworkPolicyIngressRules based on the
// provided slice of FQDNNetworkPolicyIngressRules, also returns when the next sync should happen
// based on the TTL of records
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyIngressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) ([]networking.NetworkPolicyIngressRule, *time.Duration, error) {
	log := ctrllog.FromContext(ctx)

	c, err := dns.NewClient()
	if err != nil {
		log.Error(err, "creating dns client")
		return nil, nil, err
	}

	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	// TODO what should this be?
	nextSync = uint32(r.Config.NextSyncPeriod)

	skipAAAA := fqdnNetworkPolicy.Annotations[aaaaLookupsAnnotation] == "skip" || r.Config.SkipAAAA
	if skipAAAA {
		log.V(1).Info("FQDNNetworkPolicy has AAAA lookups policy set to skip, not resolving AAAA records")
	}

	rules := make([]networking.NetworkPolicyIngressRule, 0)
	for _, rule := range fqdnNetworkPolicy.Spec.Ingress {
		records, err := c.ResolveFQDNs(ctx, rule.From, skipAAAA)
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

	minimumSync := uint32(r.Config.MinimumSyncPeriod)
	if nextSync < minimumSync {
		log.V(1).Info("Next sync is less than minimum sync period, waiting for minimum sync period")
		nextSync = minimumSync
	}

	n := time.Second * time.Duration(nextSync)

	return rules, &n, nil
}

// getNetworkPolicyEgressRules returns a slice of NetworkPolicyEgressRules based on the
// provided slice of FQDNNetworkPolicyEgressRules, also returns when the next sync should happen
// based on the TTL of records
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyEgressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) ([]networking.NetworkPolicyEgressRule, *time.Duration, error) {
	log := ctrllog.FromContext(ctx)

	c, err := dns.NewClient()
	if err != nil {
		log.Error(err, "creating dns client")
		return nil, nil, err
	}

	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	// TODO what should this be?
	nextSync = uint32(r.Config.NextSyncPeriod)

	skipAAAA := fqdnNetworkPolicy.Annotations[aaaaLookupsAnnotation] == "skip" || r.Config.SkipAAAA
	if skipAAAA {
		log.V(1).Info("FQDNNetworkPolicy has AAAA lookups policy set to skip, not resolving AAAA records")
	}

	rules := make([]networking.NetworkPolicyEgressRule, 0)
	for _, rule := range fqdnNetworkPolicy.Spec.Egress {
		records, err := c.ResolveFQDNs(ctx, rule.To, skipAAAA)
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

	minimumSync := uint32(r.Config.MinimumSyncPeriod)
	if nextSync < minimumSync {
		log.V(1).Info("Next sync is less than minimum sync period, waiting for minimum sync period")
		nextSync = minimumSync
	}

	n := time.Second * time.Duration(nextSync)

	return rules, &n, nil
}
