# 01 — Current State and Reproducible Axiom Source Pin

## 1. Probata baseline

The planning baseline is `feat/grg` at `b9a0712` on 2026-07-23. The working tree contained unrelated
untracked demo/white-paper assets when this pack was created; they are user-owned and outside this work.

`docs/CP-AUTOPILOT-LEDGER.md` is the current checkpoint authority: CP7 and the bounded CP8 flagship pilot
are certified; full production CP8 remains open. `docs/BUILD-STATUS.md` is stale and is not a migration
input.

### 1.1 Authentication

| Concern | Current implementation | Disposition |
|---|---|---|
| Human provider selection | `backend/app/api/deps.py::identity_provider` | evolve |
| Axiom password proxy | `POST /api/auth/login` → Axiom `/auth/login` | demo compatibility only |
| Token verification | RS256, JWKS, issuer, audience, `exp`, `sub` | keep and harden |
| Principal construction | `backend/app/adapters/identity/axiom.py::map_claims` | replace entitlement authority |
| Local persona provider | hardcoded Python persona directory + HS256 | test/dev only; forbid in production |
| Browser session | token in `sessionStorage`; password form | migrate to OIDC Authorization Code + PKCE |
| Signing key | current vendored Axiom generates at startup | replace with persistent secret-backed key |

### 1.2 Platform authorization

| Concern | Current implementation | Disposition |
|---|---|---|
| Authorization seam | synchronous `AuthzPort.decide` | evolve to async batch-capable contract |
| Production adapter | `CodeMatrixAdapter` | retain as non-authoritative parity oracle |
| Decision vocabulary | `allow/read/scoped/cosign/deny` | preserve in typed Axiom contract |
| Human roles/domains | derived from JWT claims | migrate to live Axiom subject resolution |
| Resource model | optional `Agent` plus optional `domain` | replace with normalized resource envelope |
| SoD | mixture of matrix gates and domain workflow invariants | retain product invariants in Probata |
| UI capabilities | `/api/me/capabilities` over local matrix | source from Axiom decision batch after cutover |
| Outage behavior | identity fails closed; authorization has no external dependency | add explicit Axiom deny/degraded behavior |

There are approximately 190 authorization/gate references in the API and services. This is a
cross-cutting migration, not one adapter file.

### 1.3 Machine identity

Probata's `X-API-Key` path is separate from human bearer authentication. Keys are hashed in PostgreSQL,
return secrets once, carry explicit product permissions/domain/use-case scopes, and construct a
service-account `Principal` with no human role inheritance. This path stays in place during AXM.

### 1.4 Existing validation assets

- `backend/tests/unit/test_identity_local.py`
- `backend/tests/unit/test_axiom_mapping.py`
- `backend/tests/integration/test_axiom_identity.py`
- `backend/tests/contract/test_axiom_role_parity.py`
- `backend/tests/unit/test_authz.py`
- `backend/tests/unit/test_authz_m2m.py`
- API-key domain/service/endpoint/RLS/E2E suites
- persona Playwright suites and no-disclosure tests
- `scripts/validate.sh` and `scripts/reset.sh`

These are migration inputs, not proof that Axiom authorization is already live.

## 2. Current vendored Axiom snapshot

Probata's `axiom/` snapshot is materially behind the source product:

| Attribute | Probata `axiom/` |
|---|---|
| Maven artifact version | `1.0.0` |
| Spring Boot | `3.5.3` |
| Java | 21 |
| main Java sources | 65 |
| tests | 2 |
| Flyway migrations | 3 |
| Docker build | copies a prebuilt `target/*.jar` |
| signing key | generated at startup |
| OAuth authorization persistence | not Redis-backed |
| Policy Studio/tenancy | absent |

The semantic version `1.0.0` is not sufficient source provenance. A source commit and subtree digest are
required.

Probata-specific `axiom/provision_uac.py` is not upstream Axiom source. It mirrors Probata personas,
roles and domains into the IAM and currently contains a legacy direct-PostgreSQL cleanup/bootstrap
exception. Preserve it as a UAC integration asset until AXM-6 replaces those operations with supported
service APIs.

## 3. Latest local Axiom authority

| Field | Value |
|---|---|
| repository | `/Users/srirajkadimisetty/projects/orchestrator-demo` |
| branch | `conduit-platform-next` |
| integration commit | `df3f5dd` |
| last `iam-service` source commit | `9fa1c948f6421b8605b467e456462b23319e8857` |
| last source change | 2026-07-17, Policy Studio lifecycle/runtime/break-glass integration |
| Spring Boot | `3.5.16` |
| Java | 25 |
| main Java sources | 228 |
| tests | 83 |
| Flyway migrations | V1–V14 |
| Cerbos authoring/probe version | `0.53.0` |
| `iam-service` tree | `40d7c9e9bb1c89d3e331a32a6772908b91259160` |
| `admin-ui` tree | `340ba34208f012754586f68491ef855ef98cf2a4` |
| `infra/cerbos` tree | `2ce99e20c5e0fb718bab64cba0995be10e9c2b8d` |

`df3f5dd` is the reproducible repository pin because later integration commits outside `iam-service`
affect runtime composition and persistent policy/signing storage. `9fa1c94` records the exact last
change to the Java subtree.

AXM-0 initially pins the repository and `iam-service`. Before AXM-1 imports anything, extend
`axiom/UPSTREAM-SOURCE.json` into a multi-component product manifest containing:

```json
{
  "schema_version": "axiom-upstream-product.v2",
  "repository": "orchestrator-demo",
  "branch": "conduit-platform-next",
  "integration_commit": "df3f5dd",
  "components": [
    {
      "name": "iam-service",
      "source_subtree": "iam-service",
      "last_component_commit": "9fa1c948f6421b8605b467e456462b23319e8857",
      "source_tree_hash": "<git tree id>",
      "destination": "axiom"
    },
    {
      "name": "admin-ui",
      "source_subtree": "admin-ui",
      "last_component_commit": "<git commit>",
      "source_tree_hash": "<git tree id>",
      "destination": "axiom-admin"
    },
    {
      "name": "platform-policy",
      "source_subtree": "infra/cerbos",
      "last_component_commit": "<git commit>",
      "source_tree_hash": "<git tree id>",
      "destination": "axiom-platform-policy",
      "file_allowlist_hash": "<canonical allowlist hash>"
    }
  ],
  "imported_at": "<UTC timestamp>",
  "excluded": ["target", ".wolf", "demo data not approved for Probata"]
}
```

The tree hash must be computed from Git, not from file timestamps.

## 4. Axiom product slice to adopt

### 4.1 Identity and platform-policy service

Import the complete `iam-service` source/build/test/migration tree, excluding build output and local
secrets. It remains a separately deployed Java/Spring service.

### 4.2 Axiom administration product

Import `admin-ui` source, package lock, build configuration, design system and tests into
`uac/axiom-admin`. It remains the separate console for:

- users, roles, groups, domains and tenant administration;
- Axiom platform-policy authoring/review/promotion/rollback;
- consequence review and examiner evidence;
- break-glass administration; and
- Axiom audit.

It does not become Probata's application shell and cannot author Probata governance/clearance policy.

### 4.3 Isolated platform Cerbos package

Import this exact initial allowlist from `infra/cerbos` into `uac/axiom-platform-policy`:

```text
config.yaml
templates/tenant-deny-all.yaml
templates/break-glass-grant.yaml
policies/iam_resource.yaml
policies/iam_derived_roles.yaml
policies/policy_draft_resource.yaml
policies/policy_bundle_resource.yaml
policies/policy_approval_resource.yaml
policies/policy_studio_derived_roles.yaml
policies/policy_meta_authz_test.yaml
```

Parameterize the break-glass template and policy tests against the normalized AXM resource/action
catalogue. Exclude `agent_resource`, `domain_resource`, `relationship_resource`, `insights_resource`,
`business_derived_roles`, every Conduit `tenant_default_*`, registry/domain-segment maps and Conduit
parity/mutation fixtures. AXM-3 creates the new Probata platform-action bundle from the frozen
CodeMatrix corpus and publishes it through Axiom Policy Studio. Probata's governance Cerbos directory
remains untouched.

### 4.4 Capabilities worth adopting

- persistent signing-key support and stable `kid`;
- Redis-backed OAuth authorization state;
- mandatory canonical `tenant_id` and tenant-qualified audiences;
- standard OIDC discovery/authorization/token/userinfo/revocation endpoints;
- explicit client credentials/service-tenant binding;
- expanded identity/user/role/domain/team APIs;
- Policy Studio with grounded generation, deterministic validation, independent test generation,
  consequence diff, approval, immutable bundle promotion, rollback, runtime activation probe,
  examiner chain and break-glass lifecycle;
- atomic tenant provisioning foundations; and
- a materially larger unit/integration contract suite.

## 5. Important incompatibilities and gaps

### 5.1 No Probata-ready authorization endpoint

The newest Axiom no longer contains the old `CerbosAuthzService` used by the stale snapshot. Runtime
authorization in the orchestrator product is performed by its gateway and coverage services. Probata
must not import that gateway.

Therefore AXM requires a generic, service-authenticated Axiom batch-decision boundary that resolves the
subject live and evaluates platform policy. Adding that contract upstream is a prerequisite to making
Axiom authoritative in Probata.

### 5.2 JWT still contains entitlements

The newest Axiom emits `roles`, `permissions`, `segments`, `admin_domains` and `classification` claims.
Those are useful compatibility and UI hints in the orchestrator product, but Probata's locked
architecture says entitlements are read live and never trusted from a JWT. Probata may compare them in
shadow telemetry; it must not use them to grant after AXM cutover.

### 5.3 Upstream enterprise IdP federation is not present

The pinned Axiom source is an OAuth/OIDC authorization server for its own principal store, but it does
not currently implement upstream Okta/Entra/Ping OIDC federation. The production topology is locked as:

```text
customer IdP → Axiom federation broker/subject link → Axiom-issued Probata token
```

AXM-2 must add the broker/linking boundary. The external identity key is `(upstream_issuer,
upstream_subject)` and maps to exactly one pre-provisioned Axiom tenant/principal. Unknown or ambiguous
links deny; just-in-time login cannot create a role, domain, tenant or default grant. The reference demo
may use Axiom-local identities only under the explicit demo flag.

### 5.4 Database and seed lineage

The old and new projects both name migrations V1–V3, but their content and later lineage are not assumed
compatible. Do not point the new binary at an existing Probata Axiom database until Flyway checksums and
schema diffs are proven.

For the demo/reference deployment, prefer a parallel fresh Axiom database populated through supported
APIs, then compare identities/roles/domains before switching the issuer. For a customer deployment,
export/replay/verify under a migration runbook; never erase the identity database.

AXM-1 creates a V1–V14 migration-disposition ledger. For every upstream migration it identifies:

- portable schema/lifecycle DDL retained unchanged;
- demo/default-tenant/Meridian identity or policy data removed from the Probata product profile;
- Conduit-only tables/columns retained behind an inert compatibility seam or excluded with evidence;
- the deterministic overlay hash applied to the pinned source; and
- the supported API/service provisioning command that replaces each removed seed.

V13 also makes tenant lifecycle ownership fail closed: the durable BUSY row is never taken over merely
because its diagnostic lease timestamp passed. A PostgreSQL session advisory lock spans external staging;
after a crash, an explicit two-person reconciliation must verify directory, runtime, Redis and audit state,
write the reconciliation evidence, and clear the row atomically. Ordinary close after uncertain ownership
cannot release it.

V14 applies the same short-transaction discipline to Policy Studio promotion. Its durable execution fence
spans external compile/probe/runtime publication, rechecks the owner row immediately before activation CAS,
and permits crash replay only after the old PostgreSQL advisory session has ended; a live owner remains BUSY.
Runtime publication is content-addressed/idempotent and the terminal ledger update is guarded so a late
failure cannot overwrite PROMOTED.

The first fresh migration gate runs before any Probata provisioning and asserts zero demo users, default
tenant grants, Meridian identities, Conduit agents, relationship/book records or demo policy bundles.
Historical customer databases are never pointed at the new binary; their migration remains blue/green.

### 5.5 Runtime dependencies

The new service requires:

- JDK 25 build/runtime images;
- Redis for OAuth authorization state;
- persistent signing-key storage;
- Axiom Postgres;
- a platform-policy runtime store/PDP;
- explicit OAuth client secrets and redirect URIs; and
- pinned Cerbos tooling for Policy Studio validation.

Do not share Redis DB/key prefixes, Postgres schemas, policy buckets or Cerbos stores with Probata
governance components.

### 5.6 Product-specific source

Do not import:

- Conduit gateway authorization/coverage code;
- registry and agent-routing runtime;
- orchestrator demo users or bankers;
- Conduit-facing `admin-ui` routes that require excluded gateway/registry/agent applications;
- generated `target/` jars/classes;
- generated `admin-ui/dist` output or `node_modules`;
- `.wolf` files;
- obsolete `user-mgmt` references; or
- Conduit-specific policy bundles as Probata platform policy.

Also remove or compile out of the `probata-platform` profile:

- legacy `PolicyController`, `PolicyService` and `LlmPolicyGenerationService`;
- relationship/book-access controllers, services and DTOs;
- Admin UI `Policies` legacy page and any related API adapter; and
- any route whose contract depends on Gateway, Registry, Agents, Relationships or Insights.

The imported Axiom Admin UI remains a separate identity/platform-policy administration console. Probata
may link to it, but it never embeds or rebrands it as Probata governance.

## 6. Source-sync rule

The source refresh is a controlled import:

1. verify the pin and clean source subtree;
2. create the source manifest;
3. refresh each approved component into its declared destination;
4. preserve Probata-owned integration artifacts explicitly;
5. run upstream Axiom tests before UAC integration tests;
6. run file-manifest checks proving no generated, denied-policy or unrelated files entered;
7. record any Probata patch on top as a small, reviewed patch set; and
8. never manually maintain two divergent implementations of the same generic Axiom contract.
