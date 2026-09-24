# Axiom on the local Meridian Kubernetes cluster

This profile installs Axiom in the `axiom` namespace and attaches it to the existing
`gateway-demo/meridian-edge` Gateway. It reuses the `meridian-gateway` GatewayClass and the
installed Envoy Gateway controller. It does not create another GatewayClass, controller, or edge.

The profile is local-only. PostgreSQL, Redis, Cerbos, and the policy-runtime volume are included to
make the Docker Desktop cluster self-contained. Production deployments should use managed storage,
a registry, a trusted certificate, and the normal Helm values described in the chart README.

The local policy-runtime claim uses the cluster's dynamic `ReadWriteOnce` storage. Axiom and Cerbos
are deliberately pinned to the same worker, so both pods can mount that claim on the one node. This
is a local profile exception. Production continues to require S3-compatible storage or a true RWX
claim as documented by the Helm chart.

## Public names

- Issuer: `https://identity.meridian.com:8443`
- Admin UI: `https://identity-admin.meridian.com:8443`
- In-cluster API Service: `axiom.axiom.svc.cluster.local:8084`
- In-cluster Admin Service: `axiom-admin.axiom.svc.cluster.local:8080`

The `:8443` suffix is the external macOS port-forward. The Gateway listeners themselves remain on
standard ports 80 and 443.

## Install

1. Load the server and admin images named in `deploy/kind/values.yaml` into the Docker Desktop Kubernetes nodes.
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

For the Argus quickstart greenfield proof, the checked-in Kind values select PostgreSQL database
`axiom_quickstart` and Redis database `1`. The original PostgreSQL `axiom` database and Redis database
`0` are not deleted. Create the empty `axiom_quickstart` database under the Axiom PostgreSQL owner
before the Helm upgrade, then run the canonical configuration publisher after the Axiom bootstrap
job succeeds. The publisher provisions new reveal-once OAuth credentials directly into its declared
Kubernetes Secrets, including the Argus Gateway broker and quickstart workload Secrets. Restart
consumers that read those Secrets through environment variables after publication.

The checked-in Meridian package also declares the quickstart service, worker Agent, task Agent, MCP
resource audience, and their reviewed exchange routes. After publishing, prove the exact identity
contract against the live Axiom API without printing credentials:

```bash
set -a
source .env
set +a
AXIOM_BASE_URL=http://127.0.0.1:8180 \
AXIOM_ISSUER=https://identity.meridian.com:8443 \
python3 scripts/verify-quickstart-agent-exchange.py
```

The verifier proves client credentials, Gateway-mediated Agent continuation, MCP and tool resource
exchange, and fail-closed bypass and cross-use-case cases. It validates Axiom's identity contract. It
does not claim that a Gateway or MCP server is deployed or that network traffic reached either one.

Do not treat a Helm rollback to the old database as a credential rollback. The publisher replaces
the broker and workload Secrets, and their previous plaintext values cannot be read back from Axiom.
A rollback must include a fresh, source-driven client/Secret reseed or a separately protected Secret
backup. Avoid direct broker-row updates or a second configuration authority.

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
