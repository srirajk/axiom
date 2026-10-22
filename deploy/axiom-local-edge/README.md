# Fresh local Axiom + Envoy Gateway edge

This is the current Axiom source image on a **new, disposable Docker Desktop Kubernetes cluster**. It is not the
historical `deploy/kind/install.sh` profile. The app and its PostgreSQL, Redis and Cerbos dependencies live in
`axiom`; Envoy Gateway's controller/data plane live in `envoy-gateway-system`, and its Gateway/TLS resources live in
`gateway-demo`. The data-plane Service is **ClusterIP**, reached only by an explicit loopback port-forward; no
LoadBalancer, NodePort, public DNS or trusted certificate is installed.

The issuer is `https://identity.meridian.com:8443` and the Admin URL is
`https://identity-admin.meridian.com:8443`. These names need local resolution to `127.0.0.1` for a browser. The
local-CA-signed, single-host leaf certificates are only for local testing. Do not use this profile with real users or secrets.
Only this local release overlay allows the Hub development origin `http://localhost:5180` in addition to the Admin
origin. CORS is not authorization: clients still need valid OAuth registration, redirect URI, scopes and user consent.

## Synthetic customer activation for the local demo

This overlay opts into a **test-only** endpoint for administrator-provisioned customers under tenant `meridian` whose
email addresses end in `@meridian.local`. It simulates email verification when no delivery provider is configured;
it does **not** prove control of a mailbox. The base Helm chart and application leave this endpoint disabled. Never
enable it for a real tenant or real customer email domain. A platform-admin bearer token is required, and each
activation is recorded as `CUSTOMER_DEMO_ACTIVATED` with `SIMULATED_DEMO` evidence.

With the foreground `installer.py expose` port-forward running, call it once with the pending demo addresses:

```bash
curl --noproxy '*' --fail-with-body \
  --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
  --resolve identity.meridian.com:8443:127.0.0.1 \
  -H "Authorization: Bearer $AXIOM_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"emails":["customer-one@meridian.local","customer-two@meridian.local"]}' \
  https://identity.meridian.com:8443/admin/tenants/meridian/ciam/demo-customers/activate
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

## Repeatable installer (recommended for the next fresh cluster)

Inspired by the Argus runtime installer's explicit stages, [`installer.py`](installer.py) separates read-only planning,
validation and rendering from installation and status. It is deliberately restricted to the `docker-desktop` context
and `hardening/phase-0-baseline` clone. It **does not** reset a cluster, replace a Secret, delete a PVC, upgrade an
existing Axiom image, or start a hidden persistent port-forward. The image tags are derived from the actual server
and Admin build inputs, built locally, then passed to Helm; the static tags in `values.yaml` are overridden. A changed
source tree against an existing Axiom release stops for a reviewed database backup and upgrade instead of silently
running Flyway against durable data.

```bash
python3 deploy/axiom-local-edge/installer.py plan
python3 deploy/axiom-local-edge/installer.py validate
python3 deploy/axiom-local-edge/installer.py dry-run
python3 deploy/axiom-local-edge/installer.py install --allow-envoy-install
python3 deploy/axiom-local-edge/installer.py status
# In a foreground terminal, while browser access is needed:
python3 deploy/axiom-local-edge/installer.py expose
```

`install` needs `--allow-envoy-install` only if the pinned Envoy Gateway chart is absent; that flag authorizes the
chart's cluster-scoped CRDs and RBAC in this disposable cluster. For a genuinely new estate with **no** local private
folder, also pass `--generate-private`; otherwise the installer preserves and verifies the existing private files.
The installer checks context, branch, tools, the selected worker, namespace Pod Security labels, chart versions,
Secret equality, offline render, server-side admission, Helm tests, route conditions, deployment readiness and a
DNS-positive/Redis-denied NetworkPolicy canary. Secret creation can resume after a partial install, but a mismatched
Secret fails closed. It prints no passwords or key material. `status` checks the deployed release; the separate
`expose` command keeps the local port-forward foreground and visible.

This installer has passed offline unit tests and `plan`/`validate`/`dry-run`/`status` against an already-running
Docker Desktop installation. **It has not yet completed a cold install on another reset cluster.** The existing
October 13 installation used manually selected image tags, so `install` deliberately refuses to adopt or upgrade it;
`status` remains valid. Do not call the workflow fully rehearsed until a fresh-cluster run completes without manual
corrections. The local Docker images and foreground port-forward are not a registry-backed or durable production
release.

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
leaf certificates expire after 30 days and require a planned local-only renewal. Keep `local-ca.crt` for clients
that validate TLS; do not use `--insecure` as a substitute outside disposable local diagnostics. This plaintext folder is convenient
for disposable local use, not suitable for production or shared workstations.

If the private folder already exists after a cluster reset, **do not run `generate` or rotate the administrator,
master, database or signing credentials**. Check the existing leaf certificates; an older local set may be self-signed
with `CA:TRUE` and lack `local-ca.crt`. Run `python3 deploy/axiom-local-edge/prepare-private.py renew-tls` to preserve
the old TLS files in an owner-only `certs/previous-*` directory and generate a local CA plus `CA:FALSE` server leaves.
This changes only local edge TLS material; `install` verifies the leaves and refuses to load malformed certificates.

## Important new-cluster security check

Docker Desktop's fresh cluster currently reports `kindnet`. Do not infer NetworkPolicy enforcement from a policy
object or CNI name alone. In this profile Redis is passwordless, so run
[`network-canary.yaml`](network-canary.yaml): its DNS lookup must succeed and the unlabeled pod must fail to reach
Redis, while the dependency Helm test succeeds from an authorized pod. A reachable Redis, failed DNS lookup, or
untested cluster is a security stop. Even a passing local canary is **not a shared-environment or production security
proof**. Delete only the canary pod after recording its result. Never weaken the cookbook's target guard or point its destructive tests at this
namespace. A later secure test profile needs an enforcing CNI and a passing denial canary before a security claim.

## Manual install from the clone root (fallback/reference)

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
   ClusterIP; verify this in the live Service before any port-forward.

   ```bash
   helm --kube-context docker-desktop upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
     --version v1.9.1 -n envoy-gateway-system --create-namespace --wait --timeout 5m
   kubectl --context docker-desktop apply --dry-run=server -f deploy/axiom-local-edge/gateway.yaml
   kubectl --context docker-desktop apply -f deploy/axiom-local-edge/gateway.yaml
   ```

5. Wait for `GatewayClass Accepted`, `Gateway Programmed`, all four HTTPRoutes `Accepted` and `ResolvedRefs`, and
   a ready Envoy data-plane pod. Its Service must be ClusterIP, with no NodePort. Start a **foreground** port-forward
   to only `127.0.0.1`, mapping local 8080/8443 to Envoy 80/443:

   ```bash
   kubectl --context docker-desktop wait --for=condition=Accepted gatewayclass/axiom-local-gateway --timeout=3m
   kubectl --context docker-desktop -n gateway-demo wait --for=condition=Programmed gateway/axiom-local-edge --timeout=3m
   kubectl --context docker-desktop -n gateway-demo get httproutes
   kubectl --context docker-desktop -n envoy-gateway-system get services
   bash deploy/axiom-local-edge/expose-local.sh
   ```

   In a second terminal, check HTTPS discovery through Envoy with the local CA, pinned hostname, exact issuer,
   Admin response and HTTP redirect. This applies only after a separately reviewed installation of the newly
   generated TLS Secrets; existing Secrets are never replaced by the generation helper:

   ```bash
   curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
     --resolve identity.meridian.com:8443:127.0.0.1 \
     https://identity.meridian.com:8443/actuator/health/readiness
   curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
     --resolve identity.meridian.com:8443:127.0.0.1 \
     https://identity.meridian.com:8443/.well-known/openid-configuration
   curl --noproxy '*' --fail --cacert deploy/axiom-local-edge/private/certs/local-ca.crt \
     --resolve identity-admin.meridian.com:8443:127.0.0.1 \
     https://identity-admin.meridian.com:8443/
   ```

   Discovery's `issuer` must exactly match `https://identity.meridian.com:8443`. The HTTPS HTTPRoutes overwrite
   `X-Forwarded-Port` with `8443` so OAuth browser-login redirects return to the same local origin; this is specific
   to the loopback-forwarded profile. Do not mistake a port-forward for a trusted public issuer. Stop the port-forward
   with Ctrl-C when done; do not leave a hidden background proxy.

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
and pod labels. The protected-token issuer remains the exact string `https://identity.meridian.com:8443`; consumers
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

A strict OIDC library that insists on fetching the advertised `https://identity.meridian.com:8443` URLs directly
cannot use this local deployment from another pod without an explicit DNS/routing and certificate-trust arrangement.
The current self-signed issuer and foreground laptop port-forward are **not** a persistent endpoint for such a
consumer. Select that consumer's actual namespace and trust model before opening any additional route; do not
modify cluster DNS or expose a LoadBalancer as an implicit quick fix.

## Recovery and removal

For an existing local release, update only the `axiom` Helm release with this profile after building the pinned
server image. Back up PostgreSQL before the upgrade and keep its PVC and the operator-owned Secrets in place. The
server's Flyway V43 migration adds broker-target authority storage; Helm rollback does not reverse a Flyway
migration. Run `helm lint`, a server-side Helm dry run, `helm upgrade axiom ... --atomic`, `helm test axiom`, and
verify Flyway V43, readiness, discovery and Admin through the existing loopback Envoy route. Do not uninstall
`axiom-dependencies` or Envoy for this application-only upgrade.

If Axiom installation fails, inspect hooks, pods and dependency health. An `--atomic` app failure rolls back that
release; it does not delete PostgreSQL, Redis, PVCs or operator-owned Secrets. Do not rotate a signing key or delete
data as a first repair. To remove this disposable estate, stop the port-forward, delete this profile's GatewayClass,
Gateway/HTTPRoutes/EnvoyProxy/ReferenceGrant and TLS Secrets, uninstall `axiom` then `axiom-dependencies`, and only
then delete `gateway-demo`, `axiom` and `envoy-gateway-system` after checking for unrelated resources. Namespace
deletion destroys the disposable PVC data; plain Helm uninstall retains some claims.

## Business scopes for this profile

`values.yaml` keeps `config.approvedBusinessScopes: example:read,example:write` as the deployment baseline (the legacy
seed list, changed only by a reviewed Helm upgrade). A tenant-specific name such as `quickstart:invoke` does **not** need
a values edit once the server image includes the tenant catalog API: a `tenant_admin` registers it with
`POST /admin/tenants/<tenant>/business-scopes` (see `configuration/README.md`). The fresh local release uses the
tenant-scope image and was smoke-tested through Envoy with an admin OAuth login: `quickstart:invoke` created with 201,
an identical repeat returned 200, and a reserved name was refused with 400. That registration does not grant a client,
person, workload or route authority. Never add a scope to the deployment baseline or re-create the database to work
around client or entitlement checks.
