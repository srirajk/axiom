# Phase 2.1 — Invocation-context contract and threat model (Axiom side)

**Status: proposed for Codex review. Not accepted.** This contract is generic: it names no Argus protocol. Where a fact
must come from a separately verified authorization source, the contract says so and Axiom's production path denies until
that source is agreed (Phase 2.2).

## 1. Objects and lifecycles

| Object | Owner | Identity | Lifecycle | Relationship |
|---|---|---|---|---|
| **Session** | Axiom (`iam_sessions`) | `sid` (UUID) | Starts at human login or client authentication; ends at logout, admin revoke, identity disable or expiry | A human workforce session is the *root session* of every run it starts (`subject_sid` in exchanged tokens) |
| **Run** | Caller (Gateway/runtime) | `run_ref`: optional, caller-written, **non-authoritative** label | Whatever the caller defines | Correlation only. One session can start any number of runs |
| **Invocation context** | Axiom (`invocation_contexts`) | `ctx`: opaque UUID minted by Axiom | `ACTIVE` → `REVOKED` (terminal); expires at `deadline` | One governed run = one root context. Carries the immutable authority below |
| **Branch** (optional) | Axiom | child context UUID | Own `ACTIVE`/`REVOKED` status; dies with any ancestor; deadline ≤ parent's | Bounded fan-out under one root context; ceiling ⊆ parent's |
| **Token** | Axiom | `jti` | ≤ exchange TTL (300 s) and ≤ context deadline | Bound to exactly one context via `ctx`/`ctx_ver`; never stores mutable state |

Sessions, runs, contexts and branches are distinct: revoking a context does not end the session; ending the session
revokes every context rooted in it; a run label never selects authority.

## 2. Fields

**Immutable** (set once at establishment, never changed by continuation):

| Field | Source | Verified by |
|---|---|---|
| `tenant_id` | subject token | Axiom (signature, active tenant) |
| `security_scope` | the trusted broker's Gateway audience | Axiom (registered broker, authenticated client) |
| `use_case` (entry application) and `entry_workload` | `act` of the Gateway-authorization subject token; one entry caller per Use Case (Phase 1.1) | Axiom (route R1, workload, client, application) |
| `originating_subject`, `identity_kind` | subject token `sub` | Axiom |
| `root_session` | `subject_sid` | Axiom (session must be active) |
| `broker`, `gateway_route` | authenticated broker client; `authority_id` of the subject token | Axiom |
| `authority_ceiling` (scopes) | ∩ of subject-token scopes, route scopes, broker scopes, destination client scopes, **and the verified authorization's approved scopes** | Axiom + **external verifier** |
| `deadline` | min(requested, verified authorization `notAfter`, configured maximum context lifetime) | Axiom + **external verifier** |
| `max_depth` | configuration | Axiom |
| `authorization_reference` | returned by the verifier | **external verifier** (recorded for audit; not presented again) |
| `parent`, `depth`, `branch_ref` | branch creation | Axiom |

**Mutable:** `status` (`ACTIVE`, `REVOKED`) and `version` (incremented on every status change, by a single conditional
`UPDATE`). Nothing records a "current actor": the actor is a property of each token (`act`), so concurrent branches
cannot overwrite one another.

**Facts Axiom cannot verify today** (must come from a separately verified authorization source, Phase 2.2): that this
subject may invoke this Use Case through this destination now (the policy decision), its approved scopes and validity.
Caller-written context IDs, run IDs and decision IDs are labels only and never establish or select authority.

## 3. Token profile (Phase 2.4)

Context-bound tokens are ordinary Axiom exchange tokens plus three claims: `ctx` (opaque context UUID), `ctx_ver`
(context version at issuance), `ctx_depth` (continuations since establishment). Subject (`sub`), current actor (`act`),
audience (`aud`), effective scope (`scope`), token ID (`jti`) and expiry (`exp` ≤ `deadline`) are already present.

## 4. Continuation rules (Phase 2.5/2.6)

At every exchange whose subject token carries `ctx`, and at every introspection of such a token, Axiom requires, from
current PostgreSQL state (no cache; a missing or unreadable row fails closed):

1. the existing edge rules (authenticated workload, intended recipient, exact allowed route, broker, tenant);
2. the context and every ancestor `ACTIVE`, `ctx_ver` equal to the current version, `now < deadline`;
3. the token's tenant, subject and root session equal the context's;
4. requested scope ⊆ subject scope ⊆ context ceiling (attenuation only), and issued `exp` ≤ deadline;
5. `ctx_depth + 1 ≤ max_depth`.

Context ID possession alone grants nothing: the ID appears only inside an Axiom-signed token, and projection
(introspection) of context facts is returned only to the token's intended recipient.

## 5. Threat model and examples

| # | Scenario | Expected |
|---|---|---|
| E1 | One user's session starts runs A and B (two contexts, same root session) | Both proceed independently; revoking A leaves B |
| E2 | Users U1 (Use Case Claims) and U2 (Use Case Wealth) through **one** Agent deployment | Each continuation carries its own `ctx`; the Agent cannot continue U1's run with U2's context or Use Case |
| E3 | Agent presents U1's context token while requesting U2's scope/destination | Denied: ceiling/route/subject mismatch |
| E4 | Caller writes a context ID, run ID or decision ID in a header or parameter | No effect on authority; establishment needs verified authorization |
| E5 | Same evidence presented for a different subject, scope or destination | Denied (verifier binding + Axiom keyed-digest uniqueness) |
| E6 | Two concurrent branches of one run | Each branch is its own row; both proceed; fan-out cap enforced atomically; neither overwrites the other |
| E7 | Context revoked while a continuation is in flight | Any token issued before the revoke committed is unusable at its next continuation or introspection; no token is issued after |
| E8 | Revoked context, token presented with a forged higher version | Signature fails; a genuine token never re-activates a revoked row |
| E9 | Mismatch: tenant B broker or Agent with tenant A context token | Denied |
| E10 | Depth exceeded, deadline passed, widened scope, repeated exchange after revocation | Denied |

## 6. Freshness and cache (Phase 0.5 alignment)

Axiom-side freshness is **immediate**: context state is read from PostgreSQL on every continuation and introspection;
there is no context cache, so there is no allow-on-miss and no staleness window inside Axiom. PostgreSQL unavailable →
fail closed. Offline JWKS receivers still cannot see revocation before `exp` (≤ 300 s); a receiver needing current
revocation must introspect.

## 7. Not decided here (questions for Codex/Argus)

- The verifiable authorization mechanism and its trust anchor (Phase 2.2). Until agreed, the production verifier denies.
- Whether a broker may end a run (revoke a context) through a broker-authenticated API; today only tenant administrators
  and session/identity lifecycle events revoke.
- Whether contexts should be **required** for every broker exchange (today optional, for Phase 1 compatibility).
