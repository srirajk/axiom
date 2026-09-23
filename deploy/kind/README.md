# Axiom on the local Meridian Kubernetes cluster

This profile installs Axiom in the `axiom` namespace and attaches it to the existing
`gateway-demo/meridian-edge` Gateway. It reuses the `meridian-gateway` GatewayClass and the
installed Envoy Gateway controller. It does not create another GatewayClass, controller, or edge.

The profile is local-only. PostgreSQL, Redis, Cerbos, and the policy-runtime volume are included to
make the Docker Desktop cluster self-contained. Production deployments should use managed storage,
a registry, a trusted certificate, and the normal Helm values described in the chart README.

## Public names

- Issuer: `https://identity.meridian.com:8443`
- Admin UI: `https://identity-admin.meridian.com:8443`
- In-cluster API Service: `axiom.axiom.svc.cluster.local:8084`
- In-cluster Admin Service: `axiom-admin.axiom.svc.cluster.local:8080`

The `:8443` suffix is the external macOS port-forward. The Gateway listeners themselves remain on
standard ports 80 and 443.

## Install

1. Load `axiom-server:local` and `axiom-admin:local` into the Docker Desktop Kubernetes nodes.
2. Create the `axiom-runtime` Secret and the immutable signing-key Secret as described in
   [the chart README](../helm/axiom/README.md).
3. Create the Cerbos ConfigMaps from `platform-policy/config.yaml` and `platform-policy/policies`.
4. Apply the local dependencies and install Axiom atomically:

```bash
kubectl apply -f deploy/kind/dependencies.yaml

helm upgrade --install axiom deploy/helm/axiom \
  --namespace axiom \
  --values deploy/kind/values.yaml \
  --atomic --wait --timeout 15m

helm test axiom --namespace axiom
```

## Attach the existing Gateway

Create `gateway-demo/axiom-identity-tls` with a certificate whose SANs contain both Meridian hostnames.
The private key belongs only in that Kubernetes Secret.

Add the four listeners once, then apply Axiom's routes and cross-namespace Service grant:

```bash
kubectl patch gateway meridian-edge \
  --namespace gateway-demo \
  --type json \
  --patch-file deploy/kind/gateway-listeners.patch.json

kubectl apply -f deploy/kind/gateway-routes.yaml
```

Do not replay the listener patch when those listener names already exist. Route application is safe to
replay.

For local browser resolution, add this host entry with administrator privileges:

```text
127.0.0.1 identity.meridian.com identity-admin.meridian.com
```

Then run the existing Gateway exposure script from the Kubernetes demo repository.

## Configure the reviewed tenant estate

Use the separate package described in [configuration/README.md](../../configuration/README.md). It
publishes through Axiom's public APIs and is not a Helm hook.

## Call Axiom from the local cluster

The local kind profile permits workloads in every namespace of this cluster to reach Axiom's HTTP
interfaces on ports 8084 and 8080. No namespace label is required. Use the cluster DNS names:

```text
http://axiom.axiom.svc.cluster.local:8084
http://axiom-admin.axiom.svc.cluster.local:8080
```

This exception exists only in `deploy/kind/dependencies.yaml`. PostgreSQL, Redis, and Cerbos remain
private to the Axiom namespace. Production environments should retain explicit namespace selectors
or approved client labels rather than enabling cluster-wide ingress.

Client applications validate the public issuer while they may use the in-cluster Service for
discovery and JWKS retrieval when their library supports separate authority and transport endpoints.

## Non-mutating acceptance

```bash
curl --fail --silent --show-error --insecure \
  --resolve identity.meridian.com:8443:127.0.0.1 \
  https://identity.meridian.com:8443/actuator/health/readiness

curl --fail --silent --show-error --insecure \
  --resolve identity.meridian.com:8443:127.0.0.1 \
  https://identity.meridian.com:8443/.well-known/openid-configuration

kubectl get pods,pvc,networkpolicy --namespace axiom
kubectl get httproute --namespace gateway-demo
```

The browser check is rendering-only: open `http://localhost:5182/login` while the Admin Service is
port-forwarded. Business applications and Argus Assured are outside this acceptance boundary.

## Remove only Axiom

```bash
helm uninstall axiom --namespace axiom
kubectl delete namespace axiom
kubectl delete persistentvolume axiom-policy-runtime --ignore-not-found
```

This does not remove the shared GatewayClass, Envoy Gateway controller, or other namespaces.
