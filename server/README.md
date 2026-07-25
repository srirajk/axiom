# Axiom for Probata

Axiom is Probata's isolated identity and platform-authorization component. It provides durable
OIDC clients, signed JWKS, tenant-scoped identity administration, platform-policy studio and audit.
It is not Probata's agent-governance policy engine and does not operate agents, evidence collection,
or contextual clearance.

## Product boundary

- **Axiom Admin** is a separate OIDC Authorization Code + S256 PKCE client at port 5181 in the canonical development compose.
- **Axiom API** serves tenant-scoped Users, Teams, Roles, Audit and the curated platform Policy Studio.
- **Probata** retains its existing login compatibility during AXM-1; its platform decisions remain
  CodeMatrix-authoritative.
- **Probata governance** and its Cerbos policy/evidence semantics are outside this component.

The fresh canonical database contains no tenant, principal, role, demo identity or grant. Use the
non-web `axiom-bootstrap` compose command with explicit tenant/admin inputs to create the first
tenant and platform administrator. The bootstrap is disabled in the normal HTTP runtime, is
idempotent only for the exact completed state, and writes one durable bootstrap audit record.

## OIDC contract

The durable registered clients are `axiom-admin` (public Authorization Code + S256 PKCE),
`probata-spa` (public Authorization Code + S256 PKCE, reserved for AXM-2 cutover), and
`probata-api` (confidential client credentials with an explicit service-tenant binding).
Axiom Admin uses issuer discovery, validates the issuer/audience/nonce/signature of the ID token,
and keeps browser tokens only in memory. It never posts a browser password or persists bearer
tokens to local storage.

## Run the canonical development stack

Use `backend/docker-compose.yml`, the sole supported Probata+Axiom composition for local reset/demo
operation. Its `dev`/demo defaults are explicitly local/reset-only; production must inject explicit
tenant, client, database and secret values, and the normal HTTP runtime remains fail-closed when
required signing material is absent. The composition has isolated Postgres, Redis, signing-key,
platform-policy-runtime and platform-Cerbos volumes. The curated `axiom-platform-policy/policies`
package is mounted read-only at Cerbos `/policies/base`; the promoted runtime volume is mounted
separately at `/policies/runtime` and `/app/runtime-policies`, so Studio publication cannot mutate
or stale-copy the curated package. Do not use the preserved `axiom/provision_uac.py` overlay for
AXM bootstrap: it is retained unchanged for separate disposition and is not the supported bootstrap
path.

The bootstrap command explicitly permits creation of the first persistent signing key and then runs the
identity-only transaction followed by the normal retryable provisioning saga. The HTTP runtime sets key
generation to false and fails startup if the signing volume is empty; a persisted key must retain RS256,
signature-use metadata and its `kid` across restart.

## Development checks

```bash
cd axiom
JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home mvn test
cd ../axiom-admin && npm run build
```

Generated `target/`, `node_modules/`, and `dist/` directories are ignored and must not be added
to product changes.
