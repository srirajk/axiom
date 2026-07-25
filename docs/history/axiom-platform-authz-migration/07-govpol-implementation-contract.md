# 07 — GOVPOL implementation contract

**Status:** normative GOVPOL specification clarification. Product Owner authorization is recorded; no GOVPOL runtime work may begin until **AXM-110 certification**.

## 1. Plane and scope boundary

This contract governs Probata Enterprise agent-governance only. Axiom platform identity/authorization and its Cerbos instance remain a separate policy plane, namespace, credential set, store, worker, audit stream and readiness probe. A governance bundle can never be deployed to Axiom Cerbos, and an Axiom platform policy can never enter the Probata governance Cerbos.

GOVPOL v1 has exactly three mutable policy layers: **Enterprise → Business Line → Use Case**. Each definition targets the canonical stable identifier for that scope. GRG environment, jurisdiction, residency, deployment and regional references are typed Evaluation Context inputs or version-pinned control facts; historical references are provenance only. They cannot select a policy version or create a fourth mutable layer. A new mutable reference outside the three-layer path fails `ambiguous_policy_path`.

## 2. Immutable objects and lifecycle

All objects are tenant-bound and use canonical JSON (sorted keys, normalized decimals, explicit schema/vocabulary versions) before hashing.

| Object | Required immutable contents | State / authority |
|---|---|---|
| Definition | id, tenant, plane, scope kind, scope id | stable identity only |
| Version | definition id, canonical source, normalized controls, parent-version vector, corpus/vocabulary versions, content hash, author | `draft → submitted → approved`; `rejected`/`withdrawn` terminal; content never changes |
| Review / Approval | version hash, actor, role, decision, reason, timestamp | append-only; author/self approval and stale hashes deny |
| Bundle | ordered Enterprise/Business Line/Use Case version ids, compiler version, canonical material, hash | immutable; isolated governance namespace only |
| Deployment intent / receipt | tenant, bundle hash, runtime namespace, idempotency key / receipt tuple below | append-only operational history |
| Activation | exact verified bundle + resolved chain, approvers, reason | only `active` activation can decide |
| Decision snapshot | context hash, exact chain, bundle/activation hashes, PDP request/result, assurance join result | immutable reconstruction evidence |

Every active Business Line and Use Case has either its own active verified version or an independently approved immutable `inherit_only` version. `inherit_only` has an empty local denial set and a stored equality proof that its effective decision vector equals its exact parent vector. A missing record is invalid, never inheritance.

## 3. Control and parent proof

The closed deny-only algebra in [06 §3.1](06-policy-realization.md#31-closed-control-algebra-and-comparison-universe) is binding. The resolver persists the ordered `(enterpriseVersion, businessLineVersion, useCaseVersion)` parent vector and the compiler retains each parent predicate. Candidate comparison uses the normalized universe `U`, not corpus sampling: a child cannot change any parent-denied input to allowed. The generated hashed corpus proves compiler/live-PDP parity at all defined boundaries.

Every referenced contextual fact has a type, source schema/version and missing-value behavior. An unknown namespace/operator, missing mandatory fact, invalid unit or non-normalizable predicate fails authoring or denies as §3.1 requires. Assurance strength, declarations, evidence and obligations remain GRG-owned.

## 4. Deterministic deployment and observation

A canonical governance bundle contains the ordered scope ids and version hashes, vocabulary/corpus/compiler versions, canonical rendered policy material and SHA-256 bundle hash. Its idempotency key is `SHA-256(tenantId | probata-governance | runtimeNamespace | bundleHash)`.

```text
desired → claimed → deployed → verified → active
                  ↘ deployment_failed | probe_failed → replay_pending
verified/active → drifted → replay_pending → deployed
```

1. The lifecycle service writes state transition, audit record and deployment intent in one PostgreSQL unit of work; only then may the outbox publish.
2. A leased, idempotent governance worker deploys with governance-only credentials. It does not call Axiom and it never performs a Cerbos call before the mutation transaction commits.
3. Before deployment, the renderer computes `expectedExternalRevision` as `SHA-256` of a canonical
   manifest ordered by exact external policy identity, exact rendered policy bytes and runtime
   namespace. The observation adapter constructs the same manifest from runtime read-back and records
   its hash as `externalRevision`; this provider-independent hash is authoritative when Cerbos exposes
   no native immutable revision. A receipt is appended only when
   `externalRevision == expectedExternalRevision`, the independently retained `bundleHash` matches the
   intent, and every hashed live-PDP probe result matches. The manifest hash and bundle hash are
   deliberately separate identities and are never compared as though they were the same value.
4. The receipt tuple is `(intentId, idempotencyKey, tenantId, runtimeNamespace, bundleHash, externalRevision, compilerVersion, corpusVersion/hash, probeRunHash, outcome, observedAt, correlationId)`. Failures retain HTTP/transport/error class, expected and observed identity, and correlation id; a successful HTTP status alone is insufficient.
5. Reconciliation compares desired intent, receipt and live observation. Missing/reordered events deduplicate by idempotency key; a sequence gap marks `replay_pending`; mismatch marks `drifted`, blocks new verified clearance and replays the exact immutable bundle.
6. Rollback is a new independently reviewed activation of a previously verified bundle and is observed through the same protocol. It is never an automatic fallback.

## 5. Legacy authority retirement and cutover

GOVPOL-001 produces a signed canonical legacy-authority inventory and migration ledger. Each entry records source location, owner, tenant/scope, authority type, source/content hash, importer result, target immutable version/bundle, parity corpus result, approval, selector transition and retirement evidence. At minimum the ledger covers the mutable `Policy` authority, `USE_CASE_CONTROLS`, seeded/static controls, legacy policy authoring/admin paths, compatibility imports, governance Cerbos static/bootstrap material, and GRG policy references.

Authority selector states are closed:

- `legacy`: permitted only before the initial verified GOVPOL activation;
- `govpol_shadow`: computes recorded parity only and cannot clear a decision;
- `govpol`: only the exact verified active bundle/chain can decide; and
- `retired`: legacy source is read-only provenance and has no decision route.

Initial cutover requires a complete signed inventory, successful backfill ledger, approval of the exact initial chain, live-PDP parity against the ledger corpus, a verified activation receipt, a one-way selector change and deployment evidence that static/bootstrap and direct legacy paths are disabled. CI/startup checks must fail if a retired source is registered as authority. A governed rollback activates a prior verified GOVPOL bundle; it never restores a legacy selector. Post-cutover evidence must prove no old source can decide.

## 6. Public mutation, clearance and UI truth

GOVPOL-005 freezes the public API, permissions, no-disclosure behavior and audit event contract before implementation. GOVPOL-101 may create unreachable persistence/read models, but no externally reachable mutation exists before GOVPOL-202 supplies the shared unit-of-work envelope. Tenant RLS applies to every read/write; unauthorized callers receive non-disclosing results. Human permission checks use Axiom platform authorization only for administration, never as governance-policy input.

The existing GRG decision formula is extended, not duplicated:

```text
cleared = evaluation_context_current
       AND exact_verified_active_enterprise_business_line_use_case_chain_allows
       AND active_assurance_declaration_and_mandatory_obligations_satisfied
```

The decision snapshot pins all three chain versions, bundle/activation, policy request/result and the existing GRG assurance/obligation evidence. No other policy path may contribute. UI states distinguish authored, approved, desired, deployed, verified, active, degraded/drifted, denied and cleared; it must not describe a database row as deployed or policy eligibility as assurance clearance.
