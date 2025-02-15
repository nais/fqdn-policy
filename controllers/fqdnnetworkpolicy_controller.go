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
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	networkingv1alpha3 "github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang/api/v1alpha3"
	"github.com/go-logr/logr"

	"github.com/miekg/dns"
	networking "k8s.io/api/networking/v1"
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
	// TODO make retry configurable
	retry = time.Second * time.Duration(10)
)

//+kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the FQDNNetworkPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *FQDNNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	log := r.Log.WithValues("fqdnnetworkpolicy", req.NamespacedName)

	// TODO(user): your logic here
	// retrieving the FQDNNetworkPolicy on which we are working
	fqdnNetworkPolicy := &networkingv1alpha3.FQDNNetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Name,
	}, fqdnNetworkPolicy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// we'll ignore not-found errors, since they can't be fixed by an immediate
			// requeue (we'll need to wait for a new notification), and we can get them
			// on deleted requests.
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

	// Updating the NetworkPolicy associated with our FQDNNetworkPolicy
	// nextSyncIn represents when we should check in again on that FQDNNetworkPolicy.
	// It's probably related to the TTL of the DNS records.
	nextSyncIn, err := r.updateNetworkPolicy(ctx, fqdnNetworkPolicy)
	if err != nil {
		log.Error(err, "unable to update NetworkPolicy")
		fqdnNetworkPolicy.Status.State = networkingv1alpha3.PendingState
		fqdnNetworkPolicy.Status.Reason = err.Error()
		n := metav1.NewTime(time.Now().Add(retry))
		fqdnNetworkPolicy.Status.NextSyncTime = &n
		if e := r.Status().Update(ctx, fqdnNetworkPolicy); e != nil {
			log.Error(e, "unable to update FQDNNetworkPolicy status")
			return ctrl.Result{}, e
		}
		return ctrl.Result{RequeueAfter: retry}, nil
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

	return ctrl.Result{RequeueAfter: *nextSyncIn}, nil
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

func (r *FQDNNetworkPolicyReconciler) updateNetworkPolicy(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) (*time.Duration, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
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
			return nil, err
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
		return nil, errors.New("NetworkPolicy missing owned-by annotation or owned by a different resource")
	}

	egressRules, nextSync, err := r.getNetworkPolicyEgressRules(ctx, fqdnNetworkPolicy)
	if err != nil {
		return nil, err
	}

	ingressRules, ingressNextSync, err := r.getNetworkPolicyIngressRules(ctx, fqdnNetworkPolicy)
	if err != nil {
		return nil, err
	}

	// We sync just after the shortest TTL between ingress and egress rules
	if ingressNextSync.Milliseconds() < nextSync.Milliseconds() {
		nextSync = ingressNextSync
	}

	networkPolicy.ObjectMeta.Name = fqdnNetworkPolicy.Name
	networkPolicy.ObjectMeta.Namespace = fqdnNetworkPolicy.Namespace

	res, err := controllerutil.CreateOrUpdate(ctx, r.Client, networkPolicy, func() error {
		// Updating NetworkPolicy
		if networkPolicy.Annotations == nil {
			networkPolicy.Annotations = make(map[string]string)
		}
		networkPolicy.Annotations[ownerAnnotation] = fqdnNetworkPolicy.Name
		networkPolicy.Spec.PodSelector = fqdnNetworkPolicy.Spec.PodSelector
		networkPolicy.Spec.PolicyTypes = fqdnNetworkPolicy.Spec.PolicyTypes
		networkPolicy.Spec.Egress = egressRules
		networkPolicy.Spec.Ingress = ingressRules
		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Info(fmt.Sprintf("NetworkPolicy %s, next sync in %s", res, nextSync))
	return nextSync, nil
}

// deleteNetworkPolicy deletes the NetworkPolicy associated with the fqdnNetworkPolicy FQDNNetworkPolicy
func (r *FQDNNetworkPolicyReconciler) deleteNetworkPolicy(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha3.FQDNNetworkPolicy) error {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)

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
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	fir := fqdnNetworkPolicy.Spec.Ingress
	rules := []networking.NetworkPolicyIngressRule{}

	// getting the nameservers from the local /etc/resolv.conf
	ns, err := getNameservers()
	if err != nil {
		log.Error(err, "unable to get nameservers")
		return nil, nil, err
	}
	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	// TODO what should this be?
	nextSync = uint32(r.Config.NextSyncPeriod)

	// TODO what do we do if nothing resolves, or if the list is empty?
	// What's the behavior of NetworkPolicies in that case?
	for _, frule := range fir {
		peers := make([]networking.NetworkPolicyPeer, 0)
		for _, from := range frule.From {
			for _, fqdn := range from.FQDNs {
				f := fqdn
				// The FQDN in the DNS request needs to end by a dot
				if l := fqdn[len(fqdn)-1]; l != '.' {
					f = fqdn + "."
				}
				c := new(dns.Client)
				c.SingleInflight = true

				// A records
				m := new(dns.Msg)
				m.SetQuestion(f, dns.TypeA)

				// TODO: We're always using the first nameserver. Should we do
				// something different? Note from Jens:
				// by default only if options rotate is set in resolv.conf
				// they are rotated. Otherwise the first is used, after a (5s)
				// timeout the next etc. So this is not too bad for now.
				r, _, err := c.Exchange(m, "["+ns[0]+"]:53")
				if err != nil {
					log.Error(err, "unable to resolve "+f)
					continue
				}
				if len(r.Answer) == 0 {
					log.V(1).Info("could not find A record for " + f)
				}
				for _, ans := range r.Answer {
					if t, ok := ans.(*dns.A); ok {
						// Adding a peer per answer
						peers = append(peers, networking.NetworkPolicyPeer{
							IPBlock: &networking.IPBlock{CIDR: t.A.String() + "/32"}})
						// We want the next sync for the FQDNNetworkPolicy to happen
						// just after the TTL of the DNS record has expired.
						// Because a single FQDNNetworkPolicy may have different DNS
						// records with different TTLs, we pick the lowest one
						// and resynchronise after that.
						if ans.Header().Ttl < nextSync {
							nextSync = ans.Header().Ttl
						}
					}
				}

				// AAAA records
				m6 := new(dns.Msg)
				m6.SetQuestion(f, dns.TypeAAAA)

				// TODO: We're always using the first nameserver. Should we do
				// something different? Note from Jens:
				// by default only if options rotate is set in resolv.conf
				// they are rotated. Otherwise the first is used, after a (5s)
				// timeout the next etc. So this is not too bad for now.
				r6, _, err := c.Exchange(m6, "["+ns[0]+"]:53")
				if err != nil {
					log.Error(err, "unable to resolve "+f)
					continue
				}
				if len(r6.Answer) == 0 {
					log.V(1).Info("could not find AAAA record for " + f)
				}
				for _, ans := range r6.Answer {
					if t, ok := ans.(*dns.AAAA); ok {
						// Adding a peer per answer
						peers = append(peers, networking.NetworkPolicyPeer{
							IPBlock: &networking.IPBlock{CIDR: t.AAAA.String() + "/128"}})
						// We want the next sync for the FQDNNetworkPolicy to happen
						// just after the TTL of the DNS record has expired.
						// Because a single FQDNNetworkPolicy may have different DNS
						// records with different TTLs, we pick the lowest one
						// and resynchronise after that.
						if ans.Header().Ttl < nextSync {
							nextSync = ans.Header().Ttl
						}
					}
				}
			}
		}

		if len(peers) == 0 {
			// If no peers have been found (most likely because the provided
			// FQDNs don't resolve to anything), then we don't create an ingress
			// rule at all to fail close. If we create one with only a "ports"
			// section, but no "to" section, we're failing open.
			log.V(1).Info("No peers found, skipping ingress rule.")
			continue
		}

		// Sort peers to prevent unnecessary updates
		slices.SortFunc(peers, func(a, b networking.NetworkPolicyPeer) int {
			return cmp.Compare(a.IPBlock.CIDR, b.IPBlock.CIDR)
		})

		rules = append(rules, networking.NetworkPolicyIngressRule{
			Ports: frule.Ports,
			From:  peers,
		})
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
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	fer := fqdnNetworkPolicy.Spec.Egress
	rules := []networking.NetworkPolicyEgressRule{}

	// getting the nameservers from the local /etc/resolv.conf
	ns, err := getNameservers()
	if err != nil {
		log.Error(err, "unable to get nameservers")
		return nil, nil, err
	}
	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	// TODO what should this be?
	nextSync = uint32(r.Config.NextSyncPeriod)

	// TODO what do we do if nothing resolves, or if the list is empty?
	// What's the behavior of NetworkPolicies in that case?
	for _, frule := range fer {
		peers := make([]networking.NetworkPolicyPeer, 0)
		for _, to := range frule.To {
			for _, fqdn := range to.FQDNs {
				f := fqdn
				// The FQDN in the DNS request needs to end by a dot
				if l := fqdn[len(fqdn)-1]; l != '.' {
					f = fqdn + "."
				}
				c := new(dns.Client)
				c.SingleInflight = true

				// A records
				m := new(dns.Msg)
				m.SetQuestion(f, dns.TypeA)

				// TODO: We're always using the first nameserver. Should we do
				// something different? Note from Jens:
				// by default only if options rotate is set in resolv.conf
				// they are rotated. Otherwise the first is used, after a (5s)
				// timeout the next etc. So this is not too bad for now.
				e, _, err := c.Exchange(m, "["+ns[0]+"]:53")
				if err != nil {
					log.Error(err, "unable to resolve "+f)
					continue
				}
				if len(e.Answer) == 0 {
					log.V(1).Info("could not find A record for " + f)
				}
				for _, ans := range e.Answer {
					if t, ok := ans.(*dns.A); ok {
						// Adding a peer per answer
						peers = append(peers, networking.NetworkPolicyPeer{
							IPBlock: &networking.IPBlock{CIDR: t.A.String() + "/32"}})
						// We want the next sync for the FQDNNetworkPolicy to happen
						// just after the TTL of the DNS record has expired.
						// Because a single FQDNNetworkPolicy may have different DNS
						// records with different TTLs, we pick the lowest one
						// and resynchronise after that.
						if ans.Header().Ttl < nextSync {
							nextSync = ans.Header().Ttl
						}
					}
				}
				// check for AAAA lookups skip annotation
				if fqdnNetworkPolicy.Annotations[aaaaLookupsAnnotation] == "skip" || r.Config.SkipAAAA {
					log.V(1).Info("FQDNNetworkPolicy has AAAA lookups policy set to skip, not resolving AAAA records")
				} else {
					// AAAA records
					m6 := new(dns.Msg)
					m6.SetQuestion(f, dns.TypeAAAA)

					// TODO: We're always using the first nameserver. Should we do
					// something different? Note from Jens:
					// by default only if options rotate is set in resolv.conf
					// they are rotated. Otherwise the first is used, after a (5s)
					// timeout the next etc. So this is not too bad for now.
					r6, _, err := c.Exchange(m6, "["+ns[0]+"]:53")
					if err != nil {
						log.Error(err, "unable to resolve "+f)
						continue
					}
					if len(r6.Answer) == 0 {
						log.V(1).Info("could not find AAAA record for " + f)
					}
					for _, ans := range r6.Answer {
						if t, ok := ans.(*dns.AAAA); ok {
							// Adding a peer per answer
							peers = append(peers, networking.NetworkPolicyPeer{
								IPBlock: &networking.IPBlock{CIDR: t.AAAA.String() + "/128"}})
							// We want the next sync for the FQDNNetworkPolicy to happen
							// just after the TTL of the DNS record has expired.
							// Because a single FQDNNetworkPolicy may have different DNS
							// records with different TTLs, we pick the lowest one
							// and resynchronise after that.
							if ans.Header().Ttl < nextSync {
								nextSync = ans.Header().Ttl
							}
						}
					}
				}
			}
		}

		if len(peers) == 0 {
			// If no peers have been found (most likely because the provided
			// FQDNs don't resolve to anything), then we don't create an egress
			// rule at all to fail close. If we create one with only a "ports"
			// section, but no "to" section, we're failing open.
			log.V(1).Info("No peers found, skipping egress rule.")
			continue
		}

		// Sort peers to prevent unnecessary updates
		slices.SortFunc(peers, func(a, b networking.NetworkPolicyPeer) int {
			return cmp.Compare(a.IPBlock.CIDR, b.IPBlock.CIDR)
		})

		rules = append(rules, networking.NetworkPolicyEgressRule{
			Ports: frule.Ports,
			To:    peers,
		})
	}

	minimumSync := uint32(r.Config.MinimumSyncPeriod)
	if nextSync < minimumSync {
		log.V(1).Info("Next sync is less than minimum sync period, waiting for minimum sync period")
		nextSync = minimumSync
	}

	n := time.Second * time.Duration(nextSync)

	return rules, &n, nil
}
