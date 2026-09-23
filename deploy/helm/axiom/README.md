# Axiom Helm chart

This chart installs the Axiom server and Admin UI into one namespace. It deliberately does not
install PostgreSQL, Redis, Cerbos, an object store, or Gateway resources. Those dependencies may
live in the same namespace, but must be healthy before Axiom is installed.

## Current topology contract

- Kubernetes 1.28 or newer.
- One Axiom server replica. This is enforced by the values schema and template validation.
- One or more stateless Admin UI replicas.
- Existing PostgreSQL, Redis, and Cerbos Services.
- An S3-compatible policy-runtime bucket is recommended. The PVC alternative requires one existing
  RWX claim mounted by both Axiom and Cerbos.
- Axiom and Cerbos must point to the same policy-runtime store.
- Gateway API resources are intentionally deferred until the cluster gateway contract is known.
- Pods meet the Kubernetes Restricted Pod Security Standard and do not mount Kubernetes API tokens.

The one-server limit is deliberate. Axiom still contains in-process web and Policy Studio session
state, a per-process active-tenant directory, and scheduled work without distributed ownership.
Scaling the Deployment before externalizing those items would create inconsistent behavior.

## 1. Create and protect the namespace

```bash
kubectl create namespace axiom
kubectl label namespace axiom \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

## 2. Create the signing-key Secret

Generate one RSA signing key outside Helm. Helm never receives private key material, so it cannot
place the key in release history or regenerate it during an upgrade.

```bash
python3 deploy/helm/axiom/scripts/create-signing-secret.py \
  --namespace axiom \
  --name axiom-signing-key \
  --apply
```

The immutable Secret contains `signing-key.json` and `jwks.json`. The bootstrap process loads the
private JWK once and stores the active signing key encrypted in PostgreSQL. Later key rotation uses
Axiom's governed signing-key lifecycle, not a Helm upgrade.

## 3. Create the runtime Secret

Store values in temporary files with mode `0600`, then create the Secret with property-shaped keys.
Spring reads it through a mounted config tree, not environment variables.

```bash
kubectl -n axiom create secret generic axiom-runtime \
  --from-file=spring.datasource.password=/secure/path/database-password \
  --from-file=iam.secrets.master-key=/secure/path/master-key \
  --from-file=axiom.bootstrap.admin-password=/secure/path/admin-password
```

For password-protected Redis also add `spring.data.redis.password`. For static S3 credentials add
`iam.policy-studio.runtime.s3.access-key` and `iam.policy-studio.runtime.s3.secret-key`, then set
`policyRuntime.s3.credentialsFromRuntimeSecret=true`. Prefer workload identity when the cluster
provides it.

The master key must be a base64-encoded 32-byte value. Kubernetes Secrets require encryption at rest
and tightly scoped namespace access; base64 encoding by itself is not encryption.

## 4. Configure the release

Create a private values file. Do not commit credentials.

```yaml
server:
  image:
    repository: registry.meridian.com/axiom/server
    tag: "1.0.0"
    digest: "sha256:..."
admin:
  image:
    repository: registry.meridian.com/axiom/admin
    tag: "1.0.0"
    digest: "sha256:..."
config:
  issuerUrl: https://identity.meridian.com
  adminPublicUrl: https://identity-admin.meridian.com
  corsAllowedOrigins: https://identity-admin.meridian.com
postgresql:
  host: axiom-postgresql
redis:
  host: axiom-redis
cerbos:
  host: axiom-cerbos
policyRuntime:
  backend: s3
  s3:
    bucket: axiom-policy-runtime
    endpoint: http://axiom-object-store:9000
    region: us-east-1
    pathStyle: true
```

## 5. Render, install, and prove the release

```bash
helm lint deploy/helm/axiom -f values-axiom.local.yaml
helm template axiom deploy/helm/axiom -n axiom -f values-axiom.local.yaml > /tmp/axiom-rendered.yaml
helm upgrade --install axiom deploy/helm/axiom \
  -n axiom --create-namespace \
  -f values-axiom.local.yaml \
  --atomic --timeout 15m
helm test axiom -n axiom --logs
```

The pre-install and pre-upgrade hooks first validate the required Secrets without printing their
content, then use Axiom's idempotent bootstrap service to create or verify the tenant, administrator,
policy runtime, audit state, and Redis namespace. Bootstrap must precede the server because the active
tenant directory is loaded at process startup. A post-install and post-upgrade hook verifies readiness
and issuer discovery. Hook Jobs have deadlines, bounded retry, and automatic cleanup.

The validated local Docker Desktop profile is in [deploy/kind](../../kind/README.md). It reuses the
existing `meridian-gateway` GatewayClass and `gateway-demo/meridian-edge` Gateway. Gateway ownership
remains outside this chart.
