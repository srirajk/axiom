# 08 — GOVPOL story acceptance matrix

**Status:** normative acceptance evidence for GOVPOL-001…406. Runtime remains blocked until **AXM-110 certification**. All tests use the isolated Probata governance Cerbos unless an item expressly verifies Axiom platform-administration authorization. Every public path proves tenant RLS, scope authorization, non-disclosure on denial, immutable audit evidence and no fallback grant.

## GOVPOL-0 — contract and migration lock

| Story | Required positive evidence | Required negative / recovery evidence |
|---|---|---|
| 001 | Signed canonical inventory and ledger enumerate mutable `Policy`, `USE_CASE_CONTROLS`, static/bootstrap Cerbos, compatibility imports, admin paths and GRG references with hashes/owners. | Unknown authority source fails inventory sign-off; changed source hash invalidates parity/cutover evidence. |
| 002 | Schema/contract fixtures create every immutable object with hashes, tenant and vocabulary/corpus versions. | Mutation of approved content, unknown operator/namespace, stale hash and cross-tenant reference fail. |
| 003 | Resolver fixture proves one Enterprise plus every active Business Line/Use Case has a verified version or approved `inherit_only`; stored equality proof matches parent vector. | Missing layer, fourth-layer reference, wrong parent id, or child widening fails with non-disclosing reason. |
| 004 | Backfill maps every ledger row to immutable target, corpus parity and governed rollback candidate. | Partial/import conflict cannot cut over; rollback activates verified GOVPOL bundle, never legacy selector. |
| 005 | Published API/permission/audit fixtures cover author, reviewer, approver, operator and reader. | Cross-tenant/no-role calls disclose neither policy nor existence; author self-approval and SoD conflict deny and audit. |

## GOVPOL-1 — immutable authoring and hierarchy

| Story | Required positive evidence | Required negative / recovery evidence |
|---|---|---|
| 101 | RLS-backed definitions/versions/current read model persist canonical hashes and tenant/scope binding. | Direct/cross-tenant writes and public mutations are unreachable before 202; content update creates no in-place change. |
| 102 | Submit/review/approve records exact version hashes, independent actors and state transitions. | Stale, self, duplicate, rejected/withdrawn approval and unauthorized read/write deny with audit. |
| 103 | Resolver returns ordered Enterprise→Business Line→Use Case vector and effective controls for canonical scope ids. | Missing/ambiguous/fourth path and mismatched parent vector fail closed; `inherit_only` equality proof is exact. |
| 104 | Normalizer proves child narrowing over `U`; boundary corpus and compiler/live-PDP outputs have matching hashes. | Allow/override, invalid interval/unit, parent deny→allow and unapproved relaxation fail authoring with consequence diff. |
| 105 | Independently approved `inherit_only` version activates and produces identical parent decision vector. | Missing row is not inheritance; self/stale approval or any local control in `inherit_only` fails. |
| 106 | Each seeded/static control migrates through service/API and ledger records target, parity and approval. | Bypass/direct insert, parity mismatch or incomplete tenant batch blocks activation and is recoverable by governed replay. |
| 107 | After GOVPOL-205 verified activation, signed cutover evidence shows only selector `govpol` and exact active verified chain may decide. | Static/imported/legacy registration causes startup/CI failure; post-cutover old-source decision probe fails closed. |

## GOVPOL-2 — bundle deployment and operational truth

| Story | Required positive evidence | Required negative / recovery evidence |
|---|---|---|
| 201 | Same ordered chain/compiler/vocabulary renders byte-identical isolated governance bundle and SHA-256 hash. | Reordered input, Axiom policy/namespace, nondeterministic render or missing parent fails compilation. |
| 202 | Every reachable lifecycle mutation commits state, audit and deployment intent atomically before publish. | Forced transaction failure leaves all three absent; duplicate/out-of-order outbox event is idempotent; no Cerbos-before-commit trace. |
| 203 | Leased worker deploys exactly once per idempotency key using governance-only credentials/namespace. | Lease loss, duplicate delivery, outage and Axiom credential/namespace attempt fail safely and queue replay. |
| 204 | Live observation records exact receipt tuple and hashes after readback plus full hashed PDP corpus. | HTTP-200-only, revision/hash mismatch or one failed probe yields `probe_failed`, no verified/active pointer. |
| 205 | Verified receipt activates exact chain and preserves preceding activation on success/failure. | Unverified, drifted or cross-tenant bundle cannot activate; deployment failure leaves preceding activation authoritative. |
| 206 | Reconciler detects drift/gaps, deduplicates replay and alerts; approved rollback reactivates prior verified bundle. | Runtime outage/reordered events block new clearance, mark degraded and never auto-fallback to static/legacy authority. |

## GOVPOL-3 — clearance and assurance join

| Story | Required positive evidence | Required negative / recovery evidence |
|---|---|---|
| 301 | After GOVPOL-107 one-way cutover, resolver exposes exact verified active three-version chain, bundle and activation to GRG integration. | Missing/unverified/drifted chain is not an allow; pre-cutover/legacy or alternate GRG reference cannot select policy. |
| 302 | Existing GRG decision snapshot contains exact policy request/result, chain, bundle and activation hashes. | Snapshot omission/hash mismatch fails attestation reconstruction; no duplicate decision model is created. |
| 303 | Evaluation Context uses policy allow only from the exact active chain alongside active Assurance Declaration roll-up. | Expired context, denied policy, missing assurance declaration or obligation prevents clearance. |
| 304 | Existing GRG staleness, not-evaluated, drift and gating-obligation consequences operate on policy input. | PDP outage/drift/missing mandatory contextual fact yields governed not-cleared consequence, never fallback grant. |
| 305 | Existing Certification Attestation reconstructs policy activation/version chain and GRG evidence. | Tampered/missing policy snapshot makes attestation non-reconstructable and blocks certification. |
| 306 | Selective re-certification receives policy-activation impact from existing GRG engine. | No second consequence engine; failed impact event replays idempotently with audit. |

## GOVPOL-4 — UX, demo and certification

| Story | Required positive evidence | Required negative / recovery evidence |
|---|---|---|
| 401 | Hierarchy screen shows exact three layers, effective controls, hashes and `inherit_only` provenance. | RLS/no-disclosure hides unauthorized scopes; no environment/region fourth policy editor is present. |
| 402 | Author/review/approval UI shows immutable version, parent diff, narrowing result and independent approver. | Invalid/widening/self/stale actions are blocked accessibly with no hidden approval path. |
| 403 | Operations UI distinguishes desired/deployed/verified/active/drifted and shows receipt/probe/replay/approved rollback evidence. | Outage, failed probe and drift never display active/cleared; credential/raw sensitive policy stays hidden. |
| 404 | Deployment×Use Case drill-down links pinned policy chain to existing GRG assurance and obligation evidence. | Denied, stale, not-evaluated and degraded paths are distinct and non-disclosing. |
| 405 | API, Postgres/RLS, governance Cerbos, outbox/replay, parity, Playwright and axe suites run as one certification gate. | Fault injection covers mutation rollback, duplicate event, worker/PDP outage, drift and legacy-authority refusal. |
| 406 | From-zero reset/demo performs hierarchy → review → deploy → verify → decision → evidence with retained audit hashes. | Reset uses service/API paths only; failed demo/rollback proves no hidden static authority and remains repeatable. |

## Evidence gate

For every row, evidence is tenant-tagged, correlation-linked and retained with the immutable version/bundle hashes. A green unit suite alone is insufficient: the certification record must include the required live governance-PDP, transaction/outbox, RLS/SoD/no-disclosure, outage/replay/drift, UI/axe and rollback evidence applicable to that story.
