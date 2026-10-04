# Phase 3 — Axiom-side authority and lifecycle contract (Gate A)

**Status: proposed, for Codex review. Nothing in Phase 3 is accepted.** Scope: the Axiom server in the isolated clone
(`axiom-changes`, branch `hardening/phase-0-baseline`). Argus, Cerbos, the Gateway, Agent runtimes and receivers are
external; where a story depends on them this contract states the Axiom half and the interface only.

Inputs: the Phase 3 strategy (3.1–3.15), the Phase 2.1 invocation-context contract
(`phase-2.1-invocation-context-contract.md`), the Phase 0.4 vocabulary and the Phase 0.5 validation contract.

## 1. Inventory: existing code against each story (before Phase 3 edits)

| Story | What already exists in Axiom | Gap that matters |
|---|---|---|
| 3.1 Code delivery | `customer_identity_challenges` (V28): 256-bit random codes stored as SHA-256, TTL ≤ 1 h, one-use `consume()`, prior codes invalidated on reissue, enumeration-resistant recovery request | **No delivery at all.** With disclosure off the code is silently dropped (registration "succeeds", nobody can verify); with `iam.ciam.local-demo-challenge-disclosure=true` the code — including a **recovery** code for any known e-mail — is returned in the HTTP response. No retry, no resend, no issuance limit, no service-level test |
| 3.2 Consent delegation | `customer_delegation_grants` (V28): customer, Agent workload, audience, scopes, free-text purpose, expiry ≤ 90 d, revoke; re-checked on every exchange and introspection (`DelegatedTokenAuthorityValidator`); suspension/recovery revoke grants | Purpose is free text written at grant time and is not an enforceable binding; nothing distinguishes two purposes for the same Agent/audience/scopes. (The controller's `@PreAuthorize` names administrator roles, but the `/ciam/**` chain accepts only customer tokens, so administrators cannot in fact record consent — verified by `ConsentPurposeIT`) |
| 3.3 Standing offline authority | Nothing. No client has `refresh_token`; customer tokens ≤ 600 s; exchanged tokens ≤ 10 min | Whole story |
| 3.4 Task resume | Nothing (no task table) | Whole story |
| 3.5 Callbacks | Nothing inbound. `ConsequenceReviewSigner` is an internal HMAC helper, not a trust anchor | Whole story; the trust anchor is a decision |
| 3.6 Branch cancellation | Phase 2 contexts: `revokeTree` already cascades to descendants only; sibling and parent survive (`InvocationContextContinuationIT`) | Only administrators can stop a branch; cancellation is not distinguished from revocation |
| 3.7 Exact-action approval | Identity-control requests (V22) canonicalize and digest a payload with two-person approval, but only for 7 identity-administration actions. `ApplicationDecisionService` can answer `cosign` without any workflow behind it | No business-action approval |
| 3.8 Single use / idempotency | Identity-control apply is effectively single-use; promotion has idempotency keys | No approval-bound token, no receiver contract |
| 3.9 Step-up | Inbound federation checks upstream `acr` at login only | No `auth_time`/`acr` in Axiom tokens; no MFA authenticator exists |
| 3.10 Team representation | `groups`/`group_members` exposed as `/teams`; SCIM group sync | No ownership of applications, clients or workloads |
| 3.11 Partner federation | Inbound OIDC workforce login (`federation/`): issuer pinning, JWKS, algorithm allow-list, audience/azp, revision fencing, link-only mapping, two-person disable/rotate | Unit tests only; no session sweep when a source is disabled; no partner selected |
| 3.12 Hosted-Agent federation | Nothing: workloads authenticate only with client secrets | Whole story; provider profiles are a decision |
| 3.13 Structured intent | `purpose` claims are server-derived (caller `purpose` is refused) but free text | No structured action binding |
| 3.14 Emergency authority | Policy Studio break-glass (C6): role/resource/action tuple, allow-listed, ≤ 60 min, two-person (author ≠ approver), HMAC-signed approval, idempotent promotion, `break_glass.granted/used` audit | No incident binding, no revocation, pending requests in memory, no token marking. **Not rebuilt here** (see D-9) |
| 3.15 Identity lifecycle | Registration of clients/workloads/brokers/routes; revoke; customer suspension; two-person secret rotation | Rotation has no overlap; no workload suspension/retirement; no ownership; no access review |

## 2. Shared authority model

Five object classes are kept distinct. None is derived from another, and none is stored inside a token.

| Object | Authoritative store | Lifetime | Holder sees |
|---|---|---|---|
| **Grant** (consent grant 3.2, standing grant 3.3, action approval 3.7) | PostgreSQL row | explicit `expires_at`; status machine | its id |
| **Token** (access token) | signed JWT; OAuth record in Redis (expiring protocol state only) | ≤ 5 min for delegated/standing/approved-action tokens | the token |
| **Renewal handle** (standing grant only) | PostgreSQL keyed digest; plaintext returned once | rotates on every use | one handle at a time |
| **Durable task** | PostgreSQL row | until completed/cancelled | its id |
| **Business execution record** | the receiver's own store | receiver-defined | — |

Common fields on every grant-like row: `id`, `tenant_id`, immutable binding facts, `status`, `version` (incremented on
every status change), `expires_at`, `revoked_at` + `revocation_reason`, `created_at`.

**Immutable vs mutable.** Binding facts (owner/subject, Agent workload, audience, scopes, purpose code, action digest,
required assurance, deadline) never change; changing any of them requires a new row. Mutable: `status`, `version`,
renewal-handle digest and generation, timestamps of use.

**Token references.** Tokens carry identifiers and versions only: `delegation_id`, `standing_grant_id` + `sg_ver`,
`approval_id` + `action_digest`, `task_id`, `ctx` + `ctx_ver`. An identifier grants nothing on its own: every
exchange, renewal, resume and introspection re-reads the row.

**Revocation propagation.** A status change commits in PostgreSQL first. Axiom refuses the next renewal, exchange,
resume or introspection immediately (no cache inside Axiom, Phase 0.5). A receiver that validates offline may accept
an already-issued token until its `exp` (≤ 5 min); "existing authority stops within the SLO" therefore requires
receivers to introspect or to accept the ≤ 5 min bound.

**Audit correlation.** Every state change writes `audit_log` synchronously (`logRequired`) with the row id as the
correlation id. Audit never contains a token, renewal handle, verification code, callback signature or evidence.

**Failure behaviour.** Unknown, stale, revoked, expired or unreadable mandatory state fails closed (`invalid_grant`
at the token endpoint, 4xx elsewhere). An absent provider or trust anchor denies; it never reports success.

## 3. Package contracts (as implemented in this campaign)

- **3.1 Delivery.** Codes go through a `CustomerCodeDeliveryProvider` adapter (none ships). A
  `customer_code_deliveries` row (V33) holds the code AES-GCM-encrypted only while `PENDING`; it is erased on `SENT`
  or `ABANDONED`. Attempts run after commit under a 60 s lease (never two workers at once), back off exponentially,
  stop at `iam.ciam.delivery.max-attempts` or the challenge expiry, and treat provider-permanent failures as final.
  A per-customer issuance limit (`iam.ciam.max-challenges-per-hour`) applies to resend and recovery, both answered
  identically for known and unknown addresses. Verification/recovery consumption is one conditional `UPDATE`. With no
  provider and no local-demo disclosure, registration, resend and recovery return 503 before anything is written. The
  local-demo disclosure still works when no provider exists and is labelled `LOCAL_DEMO`; responses say `QUEUED`,
  never "delivered".
- **3.2 Consent.** `agent_workload_purposes` (V34): code, allowed scopes, maximum validity, ACTIVE/RETIRED. A
  purpose-bound grant (`purposeCode`) must be recorded by the customer, lie within the purpose's scopes and validity.
  The exchange parameter `delegation_purpose` selects grants (it is not authority); for purpose-bound grants the token's
  `purpose` claim is the code. Use-time validation re-checks the exact grant named by `delegation_id` and the purpose's
  current state. Customer delegation stays non-transitive (no delegation to another Agent).
- **3.3 Standing grants.** `standing_grants` (V35). Approval: `POST /api/me/standing-grants` with the owner's own
  Axiom token whose `auth_time` is within `iam.standing-grant.approval-max-auth-age`; binds Agent workload, one active
  RESOURCE route/audience, scopes the owner currently holds with effect `allow` (not `cosign`/`read`/`scoped`), expiry ≤
  min(30 d, route expiry). Redemption: grant type `urn:openwolf:params:oauth:grant-type:standing-grant`, the bound
  workload's client authentication, `standing_grant`, `renewal_handle` (absent on first claim), `scope`, optional
  `task_id`; `subject_token`/`refresh_token`/`actor_token`/`assertion` are refused. Each redemption rotates a 256-bit
  handle stored as a keyed digest; presenting the immediately previous handle withdraws the grant (theft signal, which
  also means concurrent renewals with one handle end the grant). Ordering, not cross-store atomicity: the
  rotation (with the token's Axiom session and audit row) commits in PostgreSQL only after the token is signed and its
  Redis record written; a Redis failure leaves the old handle valid; a PostgreSQL commit failure leaves an orphan Redis
  record that expires with the token (+60 s store grace) and whose session was rolled back, so introspection rejects it. Token: `token_use=delegated_access`, `authority_profile=standing_grant`, `standing_grant_id`, `sg_ver`,
  `act`, TTL ≤ 5 min and ≤ grant expiry; not exchangeable onward.
- **3.4 Tasks.** `durable_tasks` (V35), workload API `/api/v1/workload/tasks` (the workload's own client-credentials
  token only). Create binds one standing grant or one invocation context (whose run was established for the calling
  Agent) at its current version; resume re-reads that authority and refuses any change; complete/cancel by the workload,
  cancel by the owner (`/api/me/tasks/{id}/cancel`) or an administrator. A cancelled task also stops tokens and
  renewals bound to it (`task_id`).
- **3.5 Callbacks.** `POST /api/v1/callbacks/tenants/{t}/tasks/{id}` with provider, timestamp, nonce, event and
  signature headers. `TaskCallbackVerifier` must bind tenant, provider, task, audience `axiom:task-callback:{tenant}`,
  time, nonce, event and body digest; default denies. Freshness 5 min; provider must be the one the task declared; task
  must be ACTIVE; `(tenant, provider, nonce)` unique. Accepted callbacks are recorded and audited only.
- **3.6 Branch cancellation.** `POST /api/v1/workload/invocation-contexts/{id}/cancel` by the establishing broker;
  `CANCELLED` + `cancelled_at` (V36), one recursive conditional update under the root lock; idempotent; distinct audit
  event; later revocation does not convert it.
- **3.7–3.9, 3.13 Approvals.** `action_approvals` (V37), API `/api/v1/action-approvals`. Canonical form
  `axiom-action-v1` (sorted keys, integers/strings/booleans only, SHA-256), binding type, receiver audience and every
  action field. Flow: request (initiator holds the scopes with `allow` or `cosign`) → approve (different principal,
  `action_approver` role checked live, fresh authentication meeting the approval's `acr` list and maximum age, exact
  digest) → confirm (initiator step-up, same requirement, exact digest) → redeem once (grant type
  `urn:openwolf:params:oauth:grant-type:approved-action`, the named workload, the exact digest, scopes ⊆ approved).
  Token carries `approval_id`, `ap_ver`, `action_type`, `action_digest`, the confirmation's `auth_time`/`acr`.
  Use-time validation (introspection) re-checks the approval row (CONSUMED, version, digest, receiver, client) and
  everything that authorized the redemption: the workload is usable (active, valid ownership), its client is active in
  the same application with the scopes, the route is usable and covers the scopes, and the initiator is active and
  still holds the scopes (`allow`/`cosign`). Consumption has the same ordering as standing renewal (no cross-store
  atomicity; a lost response consumes the approval). The Agent never receives a human token.
- **3.10/3.15 Lifecycle.** Workload `SUSPENDED` (reversible) and `RETIRED` (terminal) (V38); explicit ownership (team
  group + accountable active member) enforced live on every authority path once assigned; owner disable suspends
  durably; reactivation requires valid ownership; access reviews recorded; client-secret rotation overlap is a declared
  policy `iam.client-secret-rotation.overlap` (default 0 = existing behaviour, ≤ 24 h) checked by a client-authentication
  provider that only ever accepts the previous secret inside its window.
- **3.12 Workload federation.** Client authentication method
  `urn:openwolf:params:oauth:client-assertion-type:workload-federation`: a `WorkloadAssertionVerifier` profile (none
  configured: deny) verifies the provider's assertion; Axiom requires audience = its token endpoint, lifetime ≤ 5 min,
  an active (profile, issuer, subject) binding to exactly one usable workload whose client is the named `client_id`, and
  an unused (profile, issuer, jti). It authenticates that workload's client only; human authority still needs an
  Axiom-issued subject token.

## 4. Dependencies

3.2 depends on 3.1 for any real customer. 3.4 claims renewal only through 3.3. 3.8's business effect needs the
receiver. 3.6 extends Phase 2 contexts. 3.9 depends on an authenticator stronger than password for any assurance above
`pwd`. 3.14 must be reconciled with Policy Studio placement (Phase 0.1 deferred decision).

## 5. Decisions that cannot be made from existing contracts

| # | Decision | Default until decided |
|---|---|---|
| D-1 | Customer code delivery provider (e-mail/SMS vendor, sender domain, templates, data-processing terms) | No provider: code-dependent customer flows are refused |
| D-2 | Whether administrators may ever record consent on a customer's behalf (the controller annotation suggests it; the filter chain forbids it) | Not possible; purpose-bound consent additionally requires the customer as actor. Removing the dead administrator clause is a follow-up |
| D-3 | Callback trust anchor per provider (key distribution, algorithm, freshness window) | Deny every callback |
| D-4 | Workload-federation provider profiles (issuer, JWKS/attestation format, subject mapping) for hosted Agents and partners | Deny every assertion |
| D-5 | Assurance vocabulary and an authenticator above password (MFA/WebAuthn) for step-up; mapping of upstream `acr` | Only `pwd` (Axiom password) and freshness are satisfiable; anything higher fails closed |
| D-6 | Who may approve which action types (approver eligibility beyond the `action_approver` role) and per-action required assurance — Argus/Cerbos policy | Role check + requester-supplied requirement with a configured floor |
| D-7 | Standing-grant renewal through the Gateway (route classes, broker handling) | Standing tokens are RESOURCE-route only and not exchangeable onward |
| D-8 | Team as an acting subject (tokens issued *as* a team) | Not supported; teams own workloads only |
| D-9 | Break-glass extensions (incident binding, revocation, durable pending requests) — tied to Policy Studio placement | Existing C6 behaviour unchanged |
| D-10 | Customer standing grants and customer step-up | Not supported (workforce owners only) |
