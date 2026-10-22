# Axiom token delegation chain (RFC 8693 `act`)

Status: implemented on `hardening/phase-0-baseline` (2026-10-05), not merged or pushed; deployed only to the disposable
Docker Desktop `axiom` namespace on 2026-10-11 after the tests recorded in
`docs/operations/broker-target-release-review-2026-10-11.md`. R2 was decided by the owner on 2026-10-05
(standards-first, §4). This is Axiom's corrected reading of the
proposed consumer contract `control-plane/architecture/build/TOKEN-DELEGATION-CHAIN-CONTRACT.md` (that file was read,
not changed). Every rule below was checked against RFC 8693 and Axiom's exchange, broker, validation and introspection
paths before implementation.

## 1. What an exchanged token says

| Claim | Meaning |
|---|---|
| `sub` | The party the token acts for (person, customer or workload). Never changes across an exchange. |
| `client_id` | The OAuth client that requested this token (RFC 8693 §4.3): the workload on its own exchange, or the broker on a broker exchange. It does not by itself prove who later presents a bearer token. |
| `act` | The current actor (RFC 8693 §4.1): `sub` = workload reference, `client_id`, `workload_id`. Always regenerated from the server-side acting workload, never from request input. |
| `act.act`, `act.act.act`, … | Prior actors, most recent first, copied verbatim from the verified subject token. Informational only. |

Axiom's own validators read only the top-level `act` members; nested actors never influence an Axiom decision.
Introspection returns the chain exactly as signed.

## 2. Rules (corrected)

| # | Proposed rule | Axiom rule (as implemented) | Correction |
|---|---|---|---|
| R1 | `sub` never changes across an exchange. | Same. | None. |
| R2 | `act` is present only when the token acts for someone else; a client-credentials token has no `act`. | Same, standards-first: a service acting only for itself has no `act` — directly issued, after exchanging its own token for another audience, and across a broker hop. When another workload takes over the service's work, that workload is the only actor and the service stays `sub` (the subject is never repeated as an actor). | Decided by the owner (§4); previously exchanged software-only tokens carried a self-referential `act`. |
| R3 | The outermost `act.sub` is the party that will present the token. | The outermost `act.sub` is the **current actor**. Top-level `client_id` names the OAuth client that requested the token; on a broker-issued token it names the broker while `act.sub` remains the source workload. Neither claim alone proves who later presents a bearer token. | Overclaim: false for broker-issued tokens and contradicts the contract's own hop 4. |
| R4 | On an actor change the subject token's whole `act` becomes the new `act.act`. | Same. In Axiom the actor changes only when a destination workload redeems a broker-issued token (AGENT edge). | None. |
| R5 | A trusted broker hop does not change the actor; the broker never appears in `act`. | Same, and also a continuation by the same workload adds no level. "Same actor" means identical `sub`, `client_id` **and** `workload_id`, decided server-side by the exchange profile; never by caller input or by `sub` alone. | Ambiguity: the proposed sketch compared `sub` only. |
| R6 | Depth at most 5; deeper refused with `invalid_grant`, never truncated. | Depth = number of `act` levels in the token that would be issued (current actor included), at most 5. Checked in the exchange provider **before** anything is issued (refusal audited as `TOKEN_EXCHANGE_DENIED`) and again where the claim is written. | Ambiguity resolved (what is counted; where it is checked). |
| R7 | Each level carries `sub` (required) and `client_id` (recommended); other members allowed. | Axiom-issued levels always carry `sub`, `client_id`, `workload_id`. A subject chain is **malformed** — and refused with `invalid_grant` — if any level is not a JSON object, lacks a non-blank string `sub`, has a non-string `client_id`, or nests an `act` that is not an object. | Added the malformed-chain refusal (never repaired). |
| R8 | Nested levels copied verbatim; never rewritten or reordered. | Same; only the top level is regenerated from server-side identity. | Clarified. |
| §5 | "Argus impact: none" (Gateway reads `act.sub`; no component reads nested `act`). | Not verified here: Argus was out of scope for this Axiom-only pass. | Unverified claim; consumer owner to confirm. |

## 3. Implementation

- `server/src/main/java/com/openwolf/iam/auth/DelegationChain.java`: builds the chain and validates the subject chain
  (malformed / over-deep → `invalid_grant`).
- `JwtClaimsCustomizer` (token-exchange branch): writes `act` via `DelegationChain.forSubject` (omitted for a service
  acting for itself).
- `TokenExchangeAuthenticationProvider`: the same check before invocation binding and issuance, inside the audited
  denial path. (Defense in depth: with this pre-check removed, the customizer still refuses and the denial is still
  audited; no HTTP-observable difference.)
- `AgentExchangeAuthorityService`: `exchanged()` (marker `token_use`) and `currentActor()` (§4) replace `act` presence
  and the self-referential actor in exchange resolution, broker resolution, continuation and introspection validation.
- `SessionAwareIntrospectionAuthenticationProvider`, `CustomerTokenAuthorityValidator`, `StandingGrantService.approve`,
  `ActionApprovalService` (person's own token): also treat `token_use` as "exchange result".
- Unchanged (already keyed on `token_use`, or only ever see tokens with `act`): `DelegatedTokenAuthorityValidator`,
  `TokenExchangeSubjectAuthorityValidator`, `TokenExchangeSessionValidator`, `WorkloadClientTokenValidator`,
  `AxiomApiJwtValidator`, standing-grant and approved-action tokens (a workload acting for a person, flat `act`).

## 4. R2 decision and source binding (2026-10-05)

Decision: standards-first `act` semantics for all three situations.

| Situation | `sub` | `act` |
|---|---|---|
| A service acts for itself (client credentials, its own exchange, a broker hop of that) | the service | none |
| A service acts for a person (or customer) | the person | `{ sub: service }` |
| Service B takes over delegated work | unchanged | `{ sub: B, act: <the prior act, verbatim> }`; if the subject is a service acting for itself, `{ sub: B }` |

A broker that requests an authorized exchange appears in top-level `client_id` and never becomes an `act` actor.
The token's `client_id` is requester identity, not sender-constraining proof of the party presenting the token later.

Source binding without a self-referential actor (`AgentExchangeAuthorityService.currentActor`): with `act`, the current
actor is its top level; without one (a workload subject's exchange result), the source workload is the registered source
of the still-usable route named by `authority_id` in the caller's tenant, and that workload's OAuth client must be the
signed `sub`. The workload and client are then re-checked as active, and the route's type, audience, scopes and broker
exactly as before. "Exchange result" is recognised by `token_use` (every exchange result carries it; sign-in and
client-credentials tokens never do), not by `act`; the same marker now routes introspection to the full authority
re-check and keeps exchange results out of the customer, standing-grant owner and action-approval "person's own token"
paths, so no token that existed before is treated differently.

For a broker-owned target, the onward per-source route is intentionally replaced by the broker's tenant-scoped target
authorization. The inbound workload-to-gateway route is still required and caps the issued token's expiry. A self-acting
broker-target token has no `act`; Axiom pins its registered source with the signed `sub` and
`source_workload_id`, and pins the inbound gateway route with `source_gateway_route_id`. At each online use it re-checks
the active workload, its OAuth client, the still-usable gateway route and its scope/audience binding, broker and target.
Thus revoking the gateway entry route also invalidates an already-issued broker-target token for online introspection
and continuation. This prevents re-registration of the same client ID from inheriting an older token. The target is
broker-specific and can be revoked;
it does not encode consumer-side permission to perform a business action. Previously issued self-acting broker-target
tokens without `source_workload_id`, and all previously issued broker-target tokens without `source_gateway_route_id`,
now fail closed at introspection and exchange; they must be reissued after release. Offline JWT validation cannot
observe route or target revocation until token expiry; receivers requiring immediate revocation must introspect.

Denials preserved and re-proven: wrong tenant (another tenant's broker), wrong authenticated exchange client (a non-broker, the
source redeeming a token addressed to the destination, a sibling workload), unrouted or revoked route, wrong audience,
workload suspension, actor substitution (a re-signed token whose `sub` or `authority_id` names another workload),
widening, resource tokens terminal.

## 5. Evidence

`docs/operations/evidence/delegation-chain-2026-10-05/`.
