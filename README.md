# fqdn-policy

fqdn-policy manages [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) with fully qualified domain names (FQDNs).

FQDNs are provided through the custom resource definition (CRD) `FQDNNetworkPolicy`:

```yaml
apiVersion: networking.gke.io/v1alpha3
kind: FQDNNetworkPolicy
metadata:
  name: example
  namespace: example
spec:
  egress:
    - ports:
        - port: 443
          protocol: TCP
      to:
      - fqdns:
        - example.com
  podSelector:
    matchLabels:
      role: example
  policyTypes:
    - Egress
```

The fqdn-policy controller in turn creates (and owns) a corresponding `NetworkPolicy` with the domains now resolved to IP addresses:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: example
  namespace: example
spec:
  egress:
    - ports:
      - port: 443
        protocol: TCP
      to:
      - ipBlock:
          cidr: x.x.x.x/32
  podSelector:
    matchLabels:
      role: example
  policyTypes:
    - Egress
```

This project is a fork of the now-archived [GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang](https://github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang) project.

Differences and improvements from the original fork include:

- The controller will query all `kube-dns` pods in the cluster for DNS resolution, rather than just the first server found in `/etc/resolv.conf`.
This results in more accurate and stable policies as individual `kube-dns` pods may return different results.
- DNS resolution is cached in the controller, preventing excessive queries for `FQDNNetworkPolicy` resources with common domains.
- Resolved DNS records are cached for an additional 5 minutes after the TTL expires for stability.
- Custom annotations are removed in favor of Kubernetes-native mechanisms:
  - `fqdnnetworkpolicies.networking.gke.io/owned-by` annotation is replaced with the use of owner references.
  Existing NetworkPolicies with the same name are always adopted, unless owned by another controller.
  - `fqdnnetworkpolicies.networking.gke.io/delete-policy` annotation is removed.
  To abandon deletion of a `NetworkPolicy` when deleting an `FQDNNetworkPolicy`, use `kubectl delete fqdnnetworkpolicy <name> --cascade=orphan`.
- If there are no resolved rules for the resulting `NetworkPolicy`, the controller will automatically remove the equivalent `policyType`.
This prevents the `NetworkPolicy` from inadvertently blocking all traffic.

## Limitations

There are a few functional limitations to `FQDNNetworkPolicies`:

* Only *hostnames* are supported. In particular, you can't configure a FQDNNetworkPolicy with:
   * IP addresses or CIDR blocks. Use NetworkPolicies directly for that.
   * wildcard hostnames like `*.example.com`.
* Only A, AAAA, and CNAME records are supported.
* Records defined in the `/etc/hosts` file are not supported. Those records are probably static, so we recommend you use a normal `NetworkPolicy` for them.
* When using an [IDN](https://en.wikipedia.org/wiki/Internationalized_domain_name),
  use the punycode equivalent as the locale used inside the controller might not
  be compatible with your locale.
* Due to the how `NetworkPolicy` works, the use of `FQDNNetworkPolicies` will allow traffic to multiple hosts resolve that to the same IP address as soon as one host is allowed.

## Alternative solutions

- Some service meshes such as Istio (via [Egress gateways](https://istio.io/latest/docs/tasks/traffic-management/egress/egress-gateway/)) support proxy-based solutions for restricting traffic based on FQDNs.
This uses TLS SNI instead of DNS resolution to determine the destination, which is only applicable for HTTPS traffic.
- Some CNI plugins such as Cilium (via [CiliumNetworkPolicy](https://docs.cilium.io/en/stable/network/kubernetes/policy/#ciliumnetworkpolicy)) can intercept DNS-based traffic and enforce policies based on DNS names.
- There is an active proposal for the NetworkPolicy API project (part of [SIG-Network](https://github.com/kubernetes/community/tree/master/sig-network) in Kubernetes) to support FQDN selectors for egress traffic in [NPEP-133](https://github.com/kubernetes-sigs/network-policy-api/blob/main/npeps/npep-133-fqdn-egress-selector.md)

## Installation

Locally

```shell
helm install fqdn-policy ./charts
```

From repository
```
helm install fqdn-policy oci://europe-north1-docker.pkg.dev/nais-io/nais/feature/fqdn-policy \
    --namespace fqdn-policy \
    --create-namespace \
    --version <chart-version>
```

## Development

For available Makefile targets, run:

```shell
make help
```

## Acknowledgements

- [GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang](https://github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang) - the original project of which this is a fork of
- [delta10/fqdnnetworkpolicies](https://github.com/delta10/fqdnnetworkpolicies) - a fork of this project with similar improvements (some of which we've incorporated here)
