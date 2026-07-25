# Codex Start — Probata → Axiom Platform Authz Migration

You are the AXM master integrator in `/Users/srirajkadimisetty/projects/uac`.

## Authority

Read completely:

1. `AGENTS.md`
2. `.wolf/OPENWOLF.md`, `.wolf/anatomy.md`, `.wolf/cerebrum.md`
3. this folder's `README.md`
4. `01-current-state-and-source-pin.md`
5. `axiom-product-slice.json`
6. `02-target-architecture-and-contracts.md`
7. `03-work-orders-and-dependency-dag.md`
8. `04-acceptance-matrix.md`
9. `05-rollout-rollback-and-operations.md`
10. `06-policy-realization.md`
11. `docs/technical-architecture.md` §5.1, §8 and §19
12. `docs/implementation-plan.md` §0 and Phase 1
13. `docs/CP-AUTOPILOT-LEDGER.md`

The pack is authoritative for AXM. Do not alter its semantic contract privately to make code easier.

## Current authorization

The user authorized AXM-0/AXM-1 foundation work. Hard-stop before AXM-2 runtime/UX cutover and before any
Axiom-authoritative decision. A later explicit prompt opens each checkpoint.

## Non-negotiable boundaries

- Probata remains Python/FastAPI and remains the product.
- Axiom remains Java/Spring and owns platform identity/authorization.
- Probata governance policy stays in Probata.
- Probata governance-policy realization follows `06-policy-realization.md`; AXM-1 must not start its
  GOVPOL implementation or preserve static/compatibility controls as the target authority.
- Probata governance Cerbos is untouched.
- CodeMatrix remains authoritative until AXM-5.
- No runtime failure may fall back to a CodeMatrix grant after Axiom becomes authoritative.
- JWT entitlement claims are not live authorization authority.
- UAC API keys remain a separate M2M path in this program.
- Product SoD, RLS and no-disclosure remain in Probata.
- Import the complete approved Axiom product slice: `iam-service`, `admin-ui` identity/Policy Studio
  console and curated Axiom platform Cerbos package.
- Do not import Conduit gateway/registry/agents/apps/demo users, `user-mgmt`, `.wolf`, `target/`,
  `dist/`, `node_modules` or generated binaries.
- Do not import Conduit agent/relationship/insights policies or any Probata governance policy into
  Axiom's platform-policy runtime.
- Do not overwrite `axiom/provision_uac.py`; classify and preserve it as a Probata integration asset.
- Do not touch unrelated untracked `demo/*.png`, `docs/white-paper/` or
  `scripts/build-probata-whitepaper-pdf.py`.
- Never raw-insert seed data. Use supported HTTP/service/CLI paths.
- Never delete base/third-party Docker images.

## Execution loop

For each story:

```text
read exact contract
→ inspect current source and dirty tree
→ freeze interface/schema
→ implement the smallest vertical slice
→ focused tests and negative proof
→ independent read-only critic
→ fix and recheck
→ commit only the story-owned diff
→ update AXM evidence ledger
```

Do not claim a checkpoint complete until its acceptance table, full gate, live proof and rollback evidence
are complete.

## Model routing and cost

Use the lowest-cost profile that safely fits the work:

| Work | Model | Effort |
|---|---|---|
| source manifest, file disposition, generated fixtures, docs links, mechanical tests | GPT-5.6 Luna | medium |
| bounded Java/Python adapter/API/frontend implementation after contract freeze | GPT-5.6 Terra | medium |
| authz contract, tenant/security semantics, migration/cutover integration | GPT-5.6 Terra | high |
| routine independent checkpoint critic | GPT-5.6 Terra | high, short read-only pass |
| final AXM-5/AXM-6 security lock only, when explicitly authorized | GPT-5.6 Sol | high, short read-only pass |

Do not use Sol for routine implementation or intermediate criticism. Do not use Luna to invent authorization semantics, database
migration strategy or cutover rules. One implementation context never certifies itself.

## Parallel lanes

After the root freezes the contract:

- **Lane A — Axiom upstream:** generic subject-context/decision APIs and tests in an isolated
  `orchestrator-demo` worktree.
- **Lane B — Probata Axiom product:** pinned service/admin/policy import, isolated composition and
  product gates in the existing UAC integration session.
- **Lane C — frontend:** OIDC/PKCE only after AXM-2 opens and auth config contract freezes.
- **Lane D — critic:** read-only, no implementation ownership.

One owner controls:

- UAC `axiom/` source refresh;
- Java/Flyway lineage;
- public JSON/OpenAPI contracts;
- `PlatformAuthorizationPort`;
- Docker/issuer/client composition; and
- final integration/commits.

Workers never edit the same migration, port, router, generated client or Docker section concurrently.

## AXM-0 close report

Return:

- exact Probata and Axiom commits/tree IDs;
- source manifest and import exclusions;
- current-vs-target disposition;
- complete gate/resource inventory;
- golden corpus size/coverage/hash;
- contract compatibility results;
- baseline harness results;
- independent critic task/model/thread ID and findings;
- changed files/commits; and
- explicit statement that runtime authority did not change.

Then stop for user acceptance before AXM-1 if the initiating prompt authorized AXM-0 only.

## AXM-1 close report

Return:

- upstream source pin and built image/SBOM;
- Java/Spring/Flyway version;
- database migration/provisioning transcript;
- stable signing-key/restart proof;
- Redis OAuth/restart/outage proof;
- exact OIDC clients/issuer/audiences/redirects;
- identity/persona compatibility comparison;
- upstream Axiom and Probata identity test results;
- full Probata gate;
- rollback rehearsal;
- URL/login/clicks for the unchanged demo path; and
- explicit statement that CodeMatrix remains platform-decision authority.

Then hard-stop before AXM-2.
