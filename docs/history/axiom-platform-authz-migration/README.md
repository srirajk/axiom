# Probata → Axiom Platform Identity and Authorization Migration

**Program:** AXM  
**Status:** Authorized for specification lock and AXM-0/AXM-1 foundation only  
**Created:** 2026-07-23  
**Probata baseline:** `feat/grg` at `b9a0712`  
**Axiom source repository:** `/Users/srirajkadimisetty/projects/orchestrator-demo`  
**Axiom integration pin:** `conduit-platform-next` at `df3f5dd`  
**Latest Axiom product pin:** repository `df3f5dd`; component tree hashes recorded by AXM-1  
**Latest `iam-service` source change:** `9fa1c948f6421b8605b467e456462b23319e8857`  
**Execution entry point:** [CODEX-START.md](CODEX-START.md)

## 1. Outcome

Move Probata from its current transitional state—

```text
Axiom login/JWKS
  + JWT-carried role/domain claims
  + Probata-local CodeMatrix authorization
```

—to the locked production model:

```text
Customer IdP authenticates the human through Axiom's federation broker
                     ↓
Axiom is the sole OIDC issuer seen by Probata and maps external issuer + subject
                     ↓
Axiom resolves live identity, roles, scope and platform policy
                     ↓
Axiom decides whether the human may perform a Probata action
                     ↓
Probata enforces product invariants, RLS, SoD and no-disclosure
                     ↓
Probata authors governance policy; Probata's Cerbos evaluates cleared-for
```

The access loop is complete only when a real user signs in with OIDC, Axiom is the authoritative
platform-authorization decision source, Probata shows only the authorized estate, an entitlement
change takes effect without waiting for JWT expiry, and an Axiom outage fails closed without a
CodeMatrix grant fallback.

## 2. What this is not

- It is **not** a rename of Probata to Axiom. Probata remains the governance control plane.
- It is **not** a rewrite of Probata in Java. Probata stays Python 3.12/FastAPI; Axiom stays Java/Spring.
- It does **not** move Probata governance-policy authoring into Axiom. Axiom Policy Studio governs
  **platform access**; Probata governs **agent eligibility and contextual clearance**.
- It does **not** reuse Probata's governance Cerbos instance for platform authorization. The policy
  planes, policy stores, identities, audit streams and failure domains remain distinct.
- It does **not** trust `permissions`, `segments`, `admin_domains` or other entitlements merely because
  they appear in an otherwise valid JWT.
- It does **not** copy `user-mgmt`, generated `target/` artifacts, demo identities, Conduit gateway
  code, or unrelated orchestrator services into Probata.
- It does **not** retire Probata's scoped `X-API-Key` service-account path in this program. A future
  client-credentials migration may replace it only under a separate compatibility work order.

## 3. Why the work is needed

Probata already has important foundations:

- a real Axiom service in `axiom/`;
- RS256/JWKS verification in `AxiomIdentityProvider`;
- an injected `AuthzPort`;
- `CodeMatrixAdapter` as a pure authorization oracle;
- resource-level scope and SoD tests;
- a separate governance Cerbos adapter;
- PostgreSQL/RLS and a scoped API-key path; and
- a complete product and GRG harness.

The remaining production gap is material:

1. `get_authz()` always selects `CodeMatrixAdapter`; Axiom does not decide Probata actions.
2. Probata currently constructs human authorization scope from JWT claims rather than a live Axiom read.
3. the SPA uses a password-proxy login rather than Authorization Code + PKCE;
4. the vendored Axiom is an old snapshot with ephemeral signing keys and only three Flyway migrations;
5. the newest Axiom has stronger identity, tenancy and Policy Studio foundations but no Probata-ready
   live decision endpoint; and
6. the old externalization note was directionally correct but too small for the current product; it
   is now explicitly historical and its fallback and latest-Axiom assumptions have been reconciled.

## 4. Normative document set

Read in this order:

1. [01-current-state-and-source-pin.md](01-current-state-and-source-pin.md)
2. [`axiom-product-slice.json`](axiom-product-slice.json)
3. [02-target-architecture-and-contracts.md](02-target-architecture-and-contracts.md)
4. [03-work-orders-and-dependency-dag.md](03-work-orders-and-dependency-dag.md)
5. [04-acceptance-matrix.md](04-acceptance-matrix.md)
6. [05-rollout-rollback-and-operations.md](05-rollout-rollback-and-operations.md)
7. [06-policy-realization.md](06-policy-realization.md)
8. [CODEX-START.md](CODEX-START.md)

Existing authority still applies:

- `AGENTS.md` and `CLAUDE.md`;
- `docs/technical-architecture.md` §5.1, §8 and §19;
- `docs/implementation-plan.md` §0 and Phase 1;
- `docs/authz-externalization-design.md`, superseded where this pack is more specific;
- `docs/Capability and Governed Resource Graph/11-execution-orchestration.md`; and
- `docs/CP-AUTOPILOT-LEDGER.md`.

## 5. Program gates

| Gate | Meaning | Authority after the gate |
|---|---|---|
| AXM-0 | source and contracts are pinned; current behavior is captured | CodeMatrix remains authoritative |
| AXM-1 | latest Axiom boots in Probata and preserves existing login compatibility | CodeMatrix remains authoritative |
| AXM-2 | OIDC/PKCE and live subject context are production-ready | CodeMatrix remains authoritative |
| AXM-3 | Axiom exposes audited, tenant-safe batch platform decisions | CodeMatrix remains authoritative |
| AXM-4 | Probata runs live Axiom decisions in shadow with zero unexplained parity gaps | CodeMatrix remains authoritative |
| AXM-5 | controlled route-family cutover completes | Axiom is authoritative for cut-over routes |
| AXM-6 | legacy production paths are disabled and the access loop is certified | Axiom is authoritative everywhere |

No later gate may be declared complete because code exists. Each gate needs the exact positive,
negative, outage, parity, audit and live-persona evidence in the acceptance matrix.

## 6. Source ownership

There are two products and two repositories in this program:

| Surface | Owning repository | Rule |
|---|---|---|
| Axiom identity/authorization service | `orchestrator-demo/iam-service` → `uac/axiom` | reproducible source sync; no Probata domain imports |
| Axiom administration and Policy Studio UI | `orchestrator-demo/admin-ui` → `uac/axiom-admin` | separate Axiom console; never replace the Probata application shell |
| Axiom platform policy runtime | approved subset of `orchestrator-demo/infra/cerbos` → `uac/axiom-platform-policy` | IAM/tenancy/Policy Studio/platform-access policies only; separate from Probata governance Cerbos |
| Probata identity/authz ports and adapters | `uac/backend` | hexagonal; no Spring or gateway dependencies |
| Probata OIDC UX | `uac/frontend` | PKCE and capability-aware session states |
| Probata product SoD/no-disclosure | `uac/backend/app/domain` and services | remains authoritative in Probata |
| Probata governance policies and clearance | `uac/cerbos` and governance modules | unchanged by AXM-1; realized through the separately gated GOVPOL workstream in `06-policy-realization.md` |

Axiom upstream work lands and is independently tested before the pinned UAC product slice is refreshed.
Do not hand-edit the same Java/TypeScript/policy change independently in both repositories.

The imported Axiom product slice is intentionally complete for platform identity and authorization:

```text
axiom/                    Java identity, OAuth/OIDC, tenancy and Policy Studio APIs
axiom-admin/              Axiom identity/platform-policy administration console
axiom-platform-policy/    isolated Cerbos runtime/config/templates/platform policies/tests
```

It deliberately excludes Conduit gateway, registry, routing, agents, apps, evaluation assets, demo
personas and generated build output. Probata platform-action policies are authored for Probata from the
AXM-0 golden corpus; Conduit agent/resource policies are not renamed or reused as a shortcut.

## 7. Completion statement

This program is complete only when the user can:

1. open Probata and sign in through real Axiom OIDC;
2. see a domain-scoped catalogue based on current Axiom assignments;
3. have an administrator remove that assignment in Axiom;
4. observe the access disappear without waiting for the old JWT to expire;
5. see a correlation-safe authorization audit record with subject, action, resource, policy version
   and decision reason;
6. observe a controlled Axiom outage produce an honest degraded state and no accidental grant; and
7. recover or roll back without changing any historical Probata governance decision or attestation.
