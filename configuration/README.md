# Configure Axiom

This package provides a simple, reviewed way to configure an Axiom tenant after Axiom is running.
It publishes through Axiom's supported HTTP APIs and is safe to replay.

It is intentionally separate from the Helm chart:

- Helm installs Axiom and bootstraps the first tenant and administrator.
- This package configures the tenant's workforce directory and CIAM catalogue.
- The package is run explicitly from an operator workstation or delivery pipeline.
- The configuration is not stored in a Kubernetes ConfigMap and is not run by a Helm hook.

See [the Helm chart README](../deploy/helm/axiom/README.md) for Kubernetes installation.

## What Axiom provides

Axiom separates three kinds of identity:

| Identity | Meaning | Configured here |
|---|---|---|
| Workforce user | Administrator, engineer, steward, auditor, or other employee | `users/users.jsonl` |
| Customer | A person using a customer-facing application | `ciam/customers.jsonl` |
| Agent workload | A non-human Agent or service that can act only within delegated authority | `ciam/agent-workloads.jsonl` |

An OAuth client is not a person:

- A **public client** is a browser or mobile application. It cannot safely hold a client secret.
- A **confidential client** is a server-side service or Agent workload that can protect a credential.
- A customer signs in through a public client.
- An Agent workload authenticates through its confidential client.
- Axiom token exchange can issue a short-lived token that preserves the customer as the subject and the Agent workload as the actor.

## Package layout

```text
configuration/
  README.md
  tenants/
    meridian/
      tenant.json
      users/
        users.jsonl
      groups/
        groups.jsonl
      memberships/
        memberships.jsonl
      ciam/
        applications.jsonl
        public-clients.jsonl
        customers.jsonl
        agent-workloads.jsonl
        application-roles.jsonl
        application-memberships.jsonl
        trusted-brokers.jsonl
        agent-exchange-routes.jsonl
scripts/
  configure_axiom.py
```

Each JSONL file contains one JSON object per line. Blank lines and lines beginning with `#` are ignored.
The folder name must match the `id` in `tenant.json`.

## Bootstrap, seed, and verification entry points

These are the Axiom data-loading entry points. They have different responsibilities and should not be
treated as interchangeable.

| Entry point | Purpose | When to use it |
|---|---|---|
| `deploy/helm/axiom/templates/bootstrap-job.yaml` | Creates or verifies the first tenant and administrator during Helm installation | Every new Kubernetes installation |
| `scripts/configure_axiom.py` | Publishes the reviewed tenant package under `configuration/tenants/<tenant>` through supported Axiom APIs | Canonical workforce, CIAM, Agent workload, broker, and route configuration |
| `seed/seed_meridian.py` | Publishes the optional reference workforce directory defined by `seed/meridian_profile.py` | Local reference-directory demonstrations that explicitly need the older profile |
| `scripts/publish-ciam-demo.py` | Creates the separate, focused customer-consent demonstration and proves its replay behavior | CIAM customer delegation development and acceptance only |
| `deploy/helm/axiom/scripts/create-signing-secret.py` | Generates the RSA signing material and optionally creates the immutable Kubernetes signing Secret | Before the first Helm installation, not for tenant data |

The canonical Meridian package is:

```text
configuration/tenants/meridian/
  tenant.json
  users/users.jsonl
  groups/groups.jsonl
  memberships/memberships.jsonl
  ciam/applications.jsonl
  ciam/public-clients.jsonl
  ciam/customers.jsonl
  ciam/agent-workloads.jsonl
  ciam/application-roles.jsonl
  ciam/application-memberships.jsonl
  ciam/trusted-brokers.jsonl
  ciam/agent-exchange-routes.jsonl
```

Publish it with:

```bash
python3 scripts/configure_axiom.py --check
python3 scripts/configure_axiom.py --tenant meridian
```

The following scripts verify the running product but are not general seed scripts:

- `scripts/verify-ciam-agent-delegation.py`, customer consent and direct Agent delegation;
- `scripts/verify-public-pkce-session-lifecycle.py`, public-client and session lifecycle;
- `scripts/verify-argus-agent-exchange.py`, card workforce and multi-hop exchange;
- `scripts/verify-wealth-agent-exchange.py`, Wealth workforce, Gateway, orchestrator, specialist, and resource exchange.

`AXIOM_WEALTH_VERIFY_REVOCATION=1` deliberately revokes one reviewed route during acceptance. Run the canonical
publisher afterward to restore it. The normal verifier modes do not seed or mutate catalogue authority.

### Tenant

`tenant.json` defines the tenant identity and expected workforce and customer email suffix:

```json
{
  "id": "meridian",
  "name": "Meridian Bank",
  "slug": "meridian",
  "emailDomain": "meridian.com"
}
```

### Workforce users, groups, and memberships

Workforce users are registered through `/users`. Groups are registered through `/teams`, and memberships
refer to the stable user ID and configuration group key.

Passwords are not committed. A user record names the environment variable that supplies its initial password:

```json
{"id":"meridian-1007","username":"daniel.kim","email":"daniel.kim@meridian.com","displayName":"Daniel Kim","department":"Banking Governance","passwordEnv":"AXIOM_SEED_USER_PASSWORD"}
```

The workforce records supplied with the Meridian package, including `rm_jane` and `rm_marco`, are synthetic
local demonstration identities. They are not real customer or employee records. For the local demonstration,
the shared initial password is supplied to the publisher as:

```bash
export AXIOM_SEED_USER_PASSWORD='uac-demo-2026'
```

`configure_axiom.py` reads this value from its process environment only when it creates a missing user. It does
not load `.env` automatically, and the Helm chart intentionally does not contain demonstration user passwords.
To keep the value across local terminal sessions, it may be placed in the gitignored local `.env`, followed by
`set -a; source .env; set +a` before running the publisher. Axiom stores the resulting password hash, not the
plaintext password, so the value cannot be read back from Axiom later.

For a production workforce, prefer the customer's OIDC or SCIM source rather than maintaining a large static
user file. This package is useful for the first controlled estate, local environments, and demonstrations.

### CIAM applications and public clients

An application defines the protected product/API and audience. A public client defines the browser or mobile
application used by customers. Redirect URIs and scopes are validated as part of the OAuth contract.

Public clients never receive a client secret.

### CIAM customers

Customer records are in `ciam/customers.jsonl`, separate from workforce users and OAuth clients:

```json
{"email":"card.customer.demo@meridian.com","displayName":"Card Customer Demo","passwordEnv":"AXIOM_CUSTOMER_CARD_DEMO_PASSWORD"}
```

The publisher uses Axiom's normal customer registration and verification APIs. In a local demonstration,
`axiom.ciam.local-demo-challenge-disclosure` must be enabled so the registration API can return the one-time
verification action. In production this remains disabled, and customers complete verification through the
configured delivery channel or arrive through federation. The publisher fails rather than bypassing verification.

Customer consent and delegation grants are deliberately not stored in this package. A customer must grant and
revoke delegated authority through the CIAM journey. Preloading a grant would fabricate consent.

### Agent workloads

An Agent workload record defines:

- the owning tenant application;
- its confidential OAuth client ID;
- the stable workload reference;
- its business name;
- the scopes it may request.

When a confidential client is first created, Axiom returns its secret once. The publisher writes it to
`.local/configured-agent-clients.json` with file mode `0600`. The file is gitignored and the secret is never
printed. Move that credential into the runtime secret manager used by the Agent, then remove the local copy.

For Kubernetes workloads, declare the credential destination on the workload record:

```json
{"applicationKey":"wealth-orchestrator","clientId":"wealth-orchestrator","workloadRef":"agent:wealth-orchestrator:development","name":"Wealth Orchestrator","scopes":["wealth:review.invoke"],"kubernetesSecret":{"namespace":"wealth","name":"wealth-orchestrator-workload-oauth-client"}}
```

The publisher checks Kubernetes access before creating any confidential client. It then writes the reveal-once
credential directly to the named opaque Secret with keys `client_id` and `client_secret`. It does not put that
credential in the local output file. A replay verifies that the Secret exists and still belongs to the expected
client, but never reads or prints the secret value.

### Workforce authority, trusted broker, and Agent exchange routes

`application-roles.jsonl` and `application-memberships.jsonl` establish the exact application-scoped
workforce permission that can enter token exchange. Tenant-wide Axiom roles never substitute for this
authority.

`trusted-brokers.jsonl` registers the Argus Gateway confidential client as an exchange broker. A broker is
not an Agent workload and does not become the business actor. `agent-exchange-routes.jsonl` records the
server-owned source workload, exact Agent, Gateway, or first-party resource target, allowed business scopes,
purpose, and bounded lifetime. The publisher resolves workload references to Axiom UUIDs and creates the
routes through the governed Admin API. It never writes graph edges directly to PostgreSQL.

## End-to-end use

### 1. Start Axiom

For the local Docker Desktop Kubernetes profile, use the canonical installer. It reconciles the Helm
release, runs its smoke test, and ensures the pinned Axiom-owned Envoy identity edge exists:

```bash
./deploy/kind/install.sh
```

For another Kubernetes environment, install the chart after its platform-owned edge contract is
available and wait for the release proof to pass:

```bash
helm upgrade --install axiom deploy/helm/axiom \
  --namespace axiom --create-namespace \
  --values values-axiom.local.yaml \
  --atomic --timeout 15m

helm test axiom --namespace axiom --logs
```

For local access to a Kubernetes release:

```bash
kubectl -n axiom port-forward service/axiom 8180:8084
kubectl -n axiom port-forward service/axiom-admin 5182:8080
```

The service must return healthy before configuration starts:

```bash
curl --fail http://localhost:8180/actuator/health
```

### 2. Validate the package without changing Axiom

```bash
python3 scripts/configure_axiom.py --check
```

The check validates required fields, duplicate identities, email suffixes, membership references, application
references, and OAuth client identity conflicts.

### 3. Supply secrets outside Git

```bash
export AXIOM_BASE_URL='http://localhost:8180'
export AXIOM_ADMIN_USERNAME='admin'
export AXIOM_ADMIN_PASSWORD='replace-with-admin-password'
export AXIOM_SEED_USER_PASSWORD='replace-with-workforce-demo-password'
export AXIOM_CUSTOMER_CARD_DEMO_PASSWORD='replace-with-customer-demo-password'
```

Use a secret manager or protected pipeline variables outside a local development environment.

### 4. Publish one tenant

```bash
python3 scripts/configure_axiom.py --tenant meridian
```

The publisher performs this order through the public API:

1. Verify or provision the tenant.
2. Register groups.
3. Register workforce users.
4. Register group memberships.
5. Register CIAM applications.
6. Register public browser clients.
7. Register and verify configured customer accounts.
8. Register confidential Agent clients and Agent workloads.
9. Register the trusted Argus Gateway broker and its confidential client.
10. Register the reviewed Agent, Gateway, and first-party resource exchange routes.
11. Store newly issued Agent and broker credentials in their declared Kubernetes Secrets, or in the local
    protected output file only when no Kubernetes destination is declared.

Run one tenant per invocation using an administrator authenticated to that tenant.

### 5. Replay the same package

Run the same command again:

```bash
python3 scripts/configure_axiom.py --tenant meridian
```

Existing matching records are reported as unchanged. A conflicting identity, audience, client type, scope,
membership reference, or workload binding fails closed. The publisher does not silently reconcile contract drift.

### 6. Verify the workforce journey

Open `http://localhost:5182` and sign in as the tenant administrator. Confirm:

- the four configured workforce users exist;
- the Banking and Wealth groups exist;
- each user has the expected membership;
- no user from another tenant is visible.

Then sign in as one configured workforce user and confirm the identity and group claims are present in the issued
token. Authorization still depends on Axiom policy, not group existence alone.

### 7. Verify the CIAM journey

Open `http://localhost:5182/customer/sign-in` and use the configured customer credentials. Confirm:

1. The customer signs in through the configured public browser client.
2. The customer can review the Agent workload identity, requested audience, scopes, purpose, and expiry.
3. The customer creates a bounded delegation grant.
4. The Agent authenticates with its confidential client credential.
5. OAuth token exchange returns a short-lived audience-bound token.
6. The token preserves the customer in `sub` and the Agent workload in `act`.
7. The token contains only the intersection of client, customer, and delegation scopes.
8. Revoking the grant prevents a later exchange while preserving the audit history.

The package registers the identities and clients needed for this journey. The customer action creates the consent
and delegation, because those are business events rather than static seed data.

### 8. Verify operational safety

Before accepting an environment, confirm:

- no password or OAuth secret appears in Git, logs, API responses after creation, or browser storage;
- every Kubernetes-bound Agent and broker credential exists only in its declared opaque Secret;
- any locally returned Agent client secret has been moved to the runtime secret manager;
- replay produces only `unchanged` results;
- wrong tenant, client, audience, scope, expired grant, and revoked grant are rejected;
- Axiom restart preserves the tenant, customer, workload, delegation, and audit records;
- both workforce and customer UI journeys work at the intended desktop widths.

## Adding another tenant

Copy `configuration/tenants/meridian` to a new folder, replace all tenant-specific identities and domains, then run:

```bash
python3 scripts/configure_axiom.py --check
python3 scripts/configure_axiom.py --tenant <tenant-id>
```

The first tenant and administrator still come from the Axiom bootstrap settings. Additional tenant provisioning
requires platform-admin authority. Directory and CIAM data are then published with an administrator authenticated
to the target tenant.

## What this package does not do

- It does not store configuration in a ConfigMap.
- It does not run as a Helm pre-install or post-install hook.
- It does not place passwords or OAuth secrets in source control.
- It does not pre-authorize customer consent or delegation.
- It does not replace OIDC or SCIM for a large production workforce.
- It does not rotate credentials or signing keys. Those use their governed Axiom lifecycle.
