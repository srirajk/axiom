# Fresh local Axiom + Envoy Gateway edge

This profile builds the current Axiom source for a **new, disposable Docker Desktop Kubernetes cluster**. It is not the
historical `deploy/kind/install.sh` profile. The app and its PostgreSQL, Redis and Cerbos dependencies live in
`axiom`; Envoy Gateway's controller/data plane live in `envoy-gateway-system`, and its Gateway/TLS resources live in
`gateway-demo`. The data-plane Service is a Docker Desktop **LoadBalancer** on ports 80 and 443. The installer does
not configure public DNS or trust the local CA in clients. An optional shared-edge overlay for a cluster that already
runs Argus is described below; do not expose two local load balancers on the same host port 443.

The issuer is `https://identity.meridian.com` and the Admin URL is
`https://identity-admin.meridian.com`. These names need local resolution to `127.0.0.1` for a browser. The
local-CA-signed certificate is only for local testing. Its single key pair covers the ten Meridian test hostnames
listed below; Axiom serves only the two identity hostnames. The other names remain owned by their respective
applications and are not routed to Axiom. Do not use this profile with real users or secrets.

Certificate DNS names: `identity.meridian.com`, `identity-admin.meridian.com`, `argus.meridian.com`,
`api.argus.meridian.com`, `grafana.argus.meridian.com`, `langfuse.argus.meridian.com`,
`argus-edge-dev.argus.meridian.com`, `argus-edge-uat.argus.meridian.com`, `apps-dev.meridian.com`, and
`apps-uat.meridian.com`. The leaf and key are stored as `private/certs/axiom-identity.crt` and `.key`; the installer
copies the same pair to the existing Admin TLS Secret input. The local CA is in `private/certs/local-ca.crt`.
This local release overlay allows the Admin origin, the Hub development origin `http://localhost:5180`, and
`https://argus.meridian.com` in its global CORS list. CORS is not authorization: clients still need valid OAuth
registration, redirect URI, scopes and user consent.

## Synthetic customer activation for the local demo

This overlay opts into a **test-only** endpoint for administrator-provisioned customers under tenant `meridian` whose
email addresses end in `@meridian.local`. It simulates email verification when no delivery provider is configured;
it does **not** prove control of a mailbox. The base Helm chart and application leave this endpoint disabled. Never
enable it for a real tenant or real customer email domain. A platform-admin bearer token is required, and each
activation is recorded as `CUSTOMER_DEMO_ACTIVATED` with `SIMULATED_DEMO` evidence.

After installation, call it once with the pending demo addresses:

```bash
curl --noproxy '*' --fail-with-body \
  --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
  -H "Authorization: Bearer $AXIOM_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"emails":["customer-one@meridian.local","customer-two@meridian.local"]}' \
  https://identity.meridian.com/admin/tenants/meridian/ciam/demo-customers/activate
```

Replace the example addresses with the actual pending synthetic addresses; set `AXIOM_ADMIN_TOKEN` from your existing
platform-admin login without putting its value in shell history or logs. The request is atomic: all addresses must
exist in that tenant, be administrator-provisioned, and still be pending verification. An inactive endpoint is a 404,
and a caller without platform-admin authority is refused. This endpoint is intentionally separate from ordinary CIAM
verification and must not be presented as a production activation API.

On a fresh cluster with a reset database, the Helm overlay restores the endpoint configuration, but it does not
recreate or activate customer records. Provision the synthetic customers first, then call the endpoint again. If the
database is preserved, their active state is preserved and no repeat activation is needed. The issuer hostname,
tenant and synthetic email domain are overlay values; update them together for another disposable test estate.

## Install on a reset local cluster

Use [`installer.py`](installer.py) for a reset Docker Desktop cluster. It builds the server and Admin images from
this checkout, installs the dependencies, Axiom and Envoy, then checks that they work. It only runs from
`hardening/phase-0-baseline` on the `docker-desktop` context. It will not reset the cluster, replace a Secret,
delete a PVC or upgrade an existing Axiom image. If the source has changed since the installed release, it stops
so the database and upgrade can be reviewed first. The static image tags in `values.yaml` are overridden.

From the clone root, use this path for a **fresh** Docker Desktop cluster when the matching private files already
exist. Keep those files with the same estate if its PostgreSQL data is being restored. `validate` needs a running
cluster and a Ready `desktop-worker`.

```bash
python3 deploy/axiom-local-edge/installer.py plan
python3 deploy/axiom-local-edge/installer.py validate
python3 deploy/axiom-local-edge/installer.py dry-run
python3 deploy/axiom-local-edge/installer.py install --allow-envoy-install
python3 deploy/axiom-local-edge/installer.py status
```

For a genuinely new estate with **no** `deploy/axiom-local-edge/private/` folder and no Axiom namespace, pass
`--generate-private` to **both** `validate` and `install`. Leave the other commands unchanged. Never use that flag
to replace or work around missing credentials for an existing database or Secret.

```bash
python3 deploy/axiom-local-edge/installer.py validate --generate-private
python3 deploy/axiom-local-edge/installer.py install --allow-envoy-install --generate-private
```

Verify the HTTPS LoadBalancer endpoint and exact issuer:

```bash
curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
  https://identity.meridian.com/actuator/health/readiness
curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
  https://identity.meridian.com/.well-known/openid-configuration
```

Success means `status` reports `READY`, both Helm tests and the DNS-positive/Redis-denied canary passed during
`install`, readiness returns `UP`, and discovery advertises exactly `https://identity.meridian.com` as issuer.
These checks prove this local installation, not a complete OAuth browser flow or a production-ready endpoint.
For browser use, both hostnames must resolve to the reachable LoadBalancer address and the test client must trust
`private/certs/local-ca.crt`. In this Docker Desktop cluster, the existing local hostname entries resolve to
`127.0.0.1`, which Docker Desktop serves on port 443; no port-forward is required.

`install` needs `--allow-envoy-install` only if the pinned Envoy Gateway chart is absent; that flag authorizes the
chart's cluster-scoped CRDs and RBAC in this disposable cluster. For a genuinely new estate with **no** local private
folder, also pass `--generate-private`; otherwise the installer preserves and verifies the existing private files.
The installer checks context, branch, tools, the selected worker, namespace Pod Security labels, chart versions,
Secret equality, offline render, server-side admission, Helm tests, route conditions, deployment readiness and a
DNS-positive/Redis-denied NetworkPolicy canary. Secret creation can resume after a partial install, but a mismatched
Secret fails closed. It prints no passwords or key material. `status` checks the deployed release; verify the
external HTTPS route separately with the `curl` commands above.

The 2026-10-22 loopback-only installation is historical evidence in
[`axiom-local-edge-evidence.md`](../../docs/operations/axiom-local-edge-evidence.md). The current LoadBalancer profile
uses a different exposure path. Its local Docker images and test CA are not a registry-backed production release.

### If it stops

- Wrong context or worker: check `kubectl config current-context` and `kubectl get nodes`. Do not switch to a
  shared cluster just to make the command pass.
- Missing private files: use `--generate-private` only for a new, empty estate. Otherwise recover the files that
  match the existing database and Secrets.
- Secret, release, PVC or image mismatch: stop and check what is already installed. The installer will not take
  over or replace it.
- Failed Helm test, Gateway check or network canary: inspect the named Job, Pod or route and its logs. Do not
  bypass a failed check.
- HTTPS cannot connect after `status` says `READY`: check the Envoy LoadBalancer address, its `Cluster` external
  traffic policy, port 443, local DNS and the client trust of `local-ca.crt`.

`plan` and `dry-run` do not install anything. `validate` reads the live cluster but does not change it. An install
failure may leave a partial local estate; inspect it before re-running. This installer is not a reset command.

## Optional shared Argus edge on Docker Desktop

For this disposable cluster, `attach-shared-edge.py` adds `identity.meridian.com` and
`identity-admin.meridian.com` as HTTPS listeners on **port 443 of the existing Argus load balancer**. It copies the
existing Axiom test certificates into `argus-edge`, adds only two listeners to `argus-edge/argus-edge`, and applies
the two Axiom HTTPRoutes in `gateway-demo`. Existing Argus listeners and the original private Axiom Gateway stay in
place. First retire Axiom's separate LoadBalancer exposure, then run it only after both gateways and the Axiom
services are installed:

```bash
python3 deploy/axiom-local-edge/attach-shared-edge.py
kubectl --context docker-desktop -n argus-edge get gateway argus-edge
kubectl --context docker-desktop -n gateway-demo get httproute axiom-identity-shared-edge axiom-admin-shared-edge
```

Both new routes must be `Accepted=True` and `ResolvedRefs=True`; both listeners must be `Programmed=True`.
The shared Envoy service uses port 443 for both Argus and Axiom, selected by hostname. The public issuer stays
exactly `https://identity.meridian.com`. The local leaf expires 30 days after issuance and must be rotated in both
namespaces together. The attachment script refuses to overwrite a different existing TLS Secret; rotate those
Secrets deliberately before rerunning it.

The 2026-10-27 shared-edge check used the older port-8443 profile; it does not prove the current port-443 profile.
Validate direct laptop HTTPS with the local CA after attaching. An Argus edge redeploy may also replace its Gateway
listeners; rerun the attachment script after checking the current Gateway and route state.

To remove only this optional overlay, delete the two `*-shared-edge` HTTPRoutes in `gateway-demo`, remove the two
`axiom-*` listeners from `argus-edge/argus-edge`, then delete `axiom-identity-shared-edge-tls` and
`axiom-admin-shared-edge-tls` from `argus-edge`. Preserve all other Argus listeners and Secrets.

## Local private files

Run `python3 deploy/axiom-local-edge/prepare-private.py generate` once for a new, empty estate. The owner-only,
Git-ignored `deploy/axiom-local-edge/private/` folder then contains:

```text
private/
  certs/
    local-ca.crt            local-ca.key
    axiom-identity.crt       axiom-identity.key
    axiom-admin.crt          axiom-admin.key
    signing-key.json         jwks.json
  passwords/
    axiom-admin-username     axiom-admin-password
    postgres-password       axiom-master-key
```

The username file contains `admin`; the password files contain generated values and are never printed by the
helper. Both directories are mode `0700` and files are mode `0600`. `prepare-private.py install` loads the files
into `axiom/axiom-runtime`, `axiom/axiom-signing-key`, `gateway-demo/axiom-identity-tls`, and
`gateway-demo/axiom-admin-tls`. Both commands refuse to replace existing local material or Kubernetes Secrets.
For a repeat of the same estate, `prepare-private.py ensure` verifies all four Secrets against the local files and
creates only missing ones; it refuses to overwrite a mismatch. The installer uses this resumable mode.
Preserve the matching private files and PostgreSQL data together if you plan to restore this estate after a cluster
reset; a new password or master key cannot simply be substituted into an existing database. The local-CA-signed TLS
leaf certificate expires after 30 days and requires a planned local-only renewal. Keep `local-ca.crt` for clients
that validate TLS; do not use `--insecure` as a substitute outside disposable local diagnostics. This plaintext folder is convenient
for disposable local use, not suitable for production or shared workstations.

If the private folder already exists after a cluster reset, **do not run `generate` or rotate the administrator,
master, database or signing credentials**. Run `python3 deploy/axiom-local-edge/prepare-private.py renew-tls` to
preserve the old local CA and leaf files in an owner-only `certs/previous-*` directory and generate a new local CA
and `CA:FALSE` server leaf. This retains the signing key and passwords; `install` verifies the certificates and
refuses to load malformed material. Clients that trusted the old local CA must trust the new `local-ca.crt`.

## Important new-cluster security check

Docker Desktop's fresh cluster currently reports `kindnet`. Do not infer NetworkPolicy enforcement from a policy
object or CNI name alone. In this profile Redis is passwordless, so run
[`network-canary.yaml`](network-canary.yaml): its DNS lookup must succeed and the unlabeled pod must fail to reach
Redis, while the dependency Helm test succeeds from an authorized pod. A reachable Redis, failed DNS lookup, or
untested cluster is a security stop. Even a passing local canary is **not a shared-environment or production security
proof**. Delete only the canary pod after recording its result. Never weaken the cookbook's target guard or point its destructive tests at this
namespace. A later secure test profile needs an enforcing CNI and a passing denial canary before a security claim.

## Manual install from the clone root (fallback/reference)

The installer above is the tested path. The commands below are a component-level reference, **not** a drop-in
replacement: unlike the installer, they do not derive/build current source image tags, verify Secret equality,
check ownership or run every post-install gate. Do not run them against an existing release without a reviewed
upgrade plan. In particular, the static tags in `values.yaml` may not name the current source images.

1. Verify `kubectl config current-context` is `docker-desktop`, the cluster has no pre-existing `axiom`,
   `gateway-demo` or `envoy-gateway-system` namespaces, and the image IDs for the **exact tags in**
   `deploy/axiom-local-edge/values.yaml` are available to this cluster's worker. Record the server digest. Build
   fresh images after source changes; never reuse an older tag, including `local-quickstart-rfc8693`.
2. Lint both charts, then create `axiom` and `gateway-demo` with Pod Security `restricted` labels. Generate
   owner-only local files under `private/certs/` and `private/passwords/`, then load Kubernetes Secrets from them
   without printing their values. The `private/` folder is Git-ignored but contains plaintext private material:
   do not copy it into Git, chat, or shared storage.

   ```bash
   helm lint deploy/helm/axiom-dependencies -f deploy/axiom-local-edge/dependencies-values.yaml
   helm lint deploy/helm/axiom -f deploy/axiom-local-edge/values.yaml
   kubectl --context docker-desktop create namespace axiom
   kubectl --context docker-desktop label namespace axiom \
     pod-security.kubernetes.io/enforce=restricted \
     pod-security.kubernetes.io/audit=restricted \
     pod-security.kubernetes.io/warn=restricted
   kubectl --context docker-desktop create namespace gateway-demo
   kubectl --context docker-desktop label namespace gateway-demo \
     pod-security.kubernetes.io/enforce=restricted \
     pod-security.kubernetes.io/audit=restricted \
     pod-security.kubernetes.io/warn=restricted
   python3 deploy/axiom-local-edge/prepare-private.py generate  # only when private/ does not already exist
   python3 deploy/axiom-local-edge/prepare-private.py install
   ```

3. Install dependencies, verify them, then install Axiom. Helm tests are in-cluster smoke tests, not the complete
   identity cookbook:

   ```bash
   helm --kube-context docker-desktop upgrade --install axiom-dependencies deploy/helm/axiom-dependencies \
     -n axiom -f deploy/axiom-local-edge/dependencies-values.yaml --wait --timeout 10m
   helm --kube-context docker-desktop test axiom-dependencies -n axiom --logs
   helm --kube-context docker-desktop upgrade --install axiom deploy/helm/axiom \
     -n axiom -f deploy/axiom-local-edge/values.yaml --atomic --timeout 15m
   helm --kube-context docker-desktop test axiom -n axiom --logs
   ```

4. Install the quickstart's pinned Envoy Gateway chart `v1.9.1`. The chart installs Gateway API CRDs and RBAC;
   review these cluster-scoped objects before install. The two local TLS Secrets were loaded in step 2. Then
   server-side dry-run and apply [gateway.yaml](gateway.yaml). The `EnvoyProxy` sets the data-plane Service to
   LoadBalancer with `externalTrafficPolicy: Cluster`; verify both fields in the live Service.

   ```bash
   helm --kube-context docker-desktop upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
     --version v1.9.1 -n envoy-gateway-system --create-namespace --wait --timeout 5m
   kubectl --context docker-desktop apply --dry-run=server -f deploy/axiom-local-edge/gateway.yaml
   kubectl --context docker-desktop apply -f deploy/axiom-local-edge/gateway.yaml
   ```

5. Wait for `GatewayClass Accepted`, `Gateway Programmed`, all four HTTPRoutes `Accepted` and `ResolvedRefs`, and
   a ready Envoy data-plane pod. Its LoadBalancer Service must have an address and route traffic on port 443:

   ```bash
   kubectl --context docker-desktop wait --for=condition=Accepted gatewayclass/axiom-local-gateway --timeout=3m
   kubectl --context docker-desktop -n gateway-demo wait --for=condition=Programmed gateway/axiom-local-edge --timeout=3m
   kubectl --context docker-desktop -n gateway-demo get httproutes
   kubectl --context docker-desktop -n envoy-gateway-system get services
   ```

   Check HTTPS discovery through Envoy with the local CA, exact issuer,
   Admin response and HTTP redirect. This applies only after a separately reviewed installation of the newly
   generated TLS Secrets; existing Secrets are never replaced by the generation helper:

   ```bash
   curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
     https://identity.meridian.com/actuator/health/readiness
   curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
     https://identity.meridian.com/.well-known/openid-configuration
   curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
     https://identity-admin.meridian.com/
   ```

   Discovery's `issuer` must exactly match `https://identity.meridian.com`. The HTTPS HTTPRoutes set
   `X-Forwarded-Port` to `443` so OAuth browser-login redirects return to the same origin. The local CA still needs
   explicit trust in each client.

6. Check local network denial and remove the one canary pod:

   ```bash
   kubectl --context docker-desktop apply -f deploy/axiom-local-edge/network-canary.yaml
   kubectl --context docker-desktop -n axiom logs pod/axiom-local-network-canary
   kubectl --context docker-desktop -n axiom delete pod axiom-local-network-canary
   ```

   The canary must resolve `axiom-redis.axiom.svc.cluster.local.` and report Redis access denied. Do not infer a
   denial from DNS failure. The positive control is `helm test axiom-dependencies -n axiom --logs`.

## Same-cluster consumer contract

A future client in this cluster can reach Axiom's HTTP transport at
`http://axiom.axiom.svc.cluster.local:8084` **only after** an ingress NetworkPolicy explicitly permits its namespace
and pod labels. The protected-token issuer remains the exact string `https://identity.meridian.com`; consumers
must compare JWT `iss` to that string, check audience and signature, and reject tokens when required validation
cannot be completed. The internal transport can serve discovery, JWKS, introspection and token endpoints to clients
whose libraries support an issuer distinct from their network endpoint. Do not rewrite the issuer claim to the
internal HTTP address.

The temporary [consumer-probe.yaml](consumer-probe.yaml) is a worked **connectivity** example: a restricted pod in
`axiom-consumer-probe` receives access only to Axiom's server port, then checks readiness, exact issuer metadata and
JWKS. Apply it only in a disposable namespace; remove its NetworkPolicy and namespace after the test. It does not
register a client, issue a token, test browser login or prove consumer authorization decisions. The executable
[identity cookbook](../../examples/identity_scenarios/README.md) covers the broader OAuth/OIDC contracts in its own
disposable estate and must not be pointed at this Kubernetes deployment.

A strict OIDC library that insists on fetching the advertised `https://identity.meridian.com` URLs directly
cannot use this local deployment from another pod without an explicit DNS/routing and certificate-trust arrangement.
The local CA and Docker Desktop LoadBalancer are **not** a production endpoint for such a consumer. Select that
consumer's actual namespace and trust model before opening any additional route or changing cluster DNS.

## Recovery and removal

An existing release from the older `:8443` profile has an `axiom-admin` OAuth client persisted with callback and
post-logout URLs on that port. Before upgrading that release to the port-443 profile, verify that this is the only
drift in `oauth2_registered_client` and change those two URLs to
`https://identity-admin.meridian.com/callback` and `https://identity-admin.meridian.com/login`. The bootstrap hook
intentionally refuses an unexpected registered-client change. Keep the exact old values for recovery: if Helm
rolls back, restore the old URLs before restarting the old release. This is a deployment-specific data change, not
a generic Flyway migration. The local 2026-10-31 upgrade updated one matching row, then Helm revision 4 and its
smoke test passed without resetting PostgreSQL or rotating credentials.

For an existing local release, the installer refuses a changed source image; it is **not** an upgrade command.
Back up PostgreSQL, record the current image and chart values, and review the required Flyway migrations before a
separate application-only upgrade. Keep the PVCs and operator-owned Secrets in place. Helm rollback does not undo
database migrations (this source tree includes V43 broker-target storage and V44 customer-person names). Run chart
lint and server-side dry-run, upgrade only `axiom` with `--atomic`, run `helm test axiom`, and verify migration state,
readiness, discovery and Admin through the Envoy LoadBalancer route. Do not uninstall `axiom-dependencies` or
Envoy for an application-only upgrade.

If Axiom installation fails, inspect hooks, pods and dependency health. An `--atomic` app failure rolls back that
release; it does not delete PostgreSQL, Redis, PVCs or operator-owned Secrets. Do not rotate a signing key or delete
data as a first repair. To remove this disposable estate, delete this profile's GatewayClass,
Gateway/HTTPRoutes/EnvoyProxy/ReferenceGrant and TLS Secrets, uninstall `axiom` then `axiom-dependencies`, and only
then delete `gateway-demo`, `axiom` and `envoy-gateway-system` after checking for unrelated resources. Namespace
deletion destroys the disposable PVC data; plain Helm uninstall retains some claims.

## Business scopes for this profile

`values.yaml` keeps `config.approvedBusinessScopes: example:read,example:write` as the deployment baseline (the legacy
seed list, changed only by a reviewed Helm upgrade). A tenant-specific name such as `quickstart:invoke` does **not** need
a values edit once the server image includes the tenant catalog API: a `tenant_admin` registers it with
`POST /admin/tenants/<tenant>/business-scopes` (see the [configuration guide](../../configuration/README.md)).
An earlier 2026-10-04 installation smoke-tested that API through Envoy with an admin OAuth login:
`quickstart:invoke` created with 201, an identical
repeat returned 200, and a reserved name was refused with 400. Those results are not a claim that the fresh
2026-10-22 database already contains that scope. Registration does not grant a client, person, workload or route
authority. Never add a scope to the deployment baseline or re-create the database to work around client or
entitlement checks.
