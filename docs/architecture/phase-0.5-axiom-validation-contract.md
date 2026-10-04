# Phase 0.5 — Axiom-side validation and freshness contract

Status: **Axiom-side source baseline in progress; joint Argus contract parked at the owner's request.** This document records current behavior and safe boundaries. It does not approve an external receiver, define an Argus context lookup, or claim that offline signature verification enforces revocation.

## Current Axiom enforcement points

| Boundary | Current validation | Revocation/freshness meaning | Limit |
|---|---|---|---|
| Axiom admin resource API | `SecurityConfig.jwtDecoder`: issuer/signature/time, `AxiomApiJwtValidator` requiring one `axiom-api` audience and `at+jwt`, and `SessionTokenValidator` | Session and root `subject_sid`, when present, are checked against the durable Axiom session service on decoding. Failure or session-store exception rejects the token. | This is for Axiom's own API, not an Argus or arbitrary resource receiver. |
| RFC 8693 exchange subject | `tokenExchangeSubjectJwtDecoder`: issuer/signature/time, `TokenExchangeSessionValidator`, then `TokenExchangeSubjectAuthorityValidator` | Session-bearing subjects require current session state; an original sessionless client-credentials workload has a narrow bypass and must then pass active client/workload/tenant/audience checks. Customer and Agent authority is re-evaluated before exchange. | The bypass is not a generic exemption for exchanged or human tokens. |
| RFC 7662 introspection | `SessionAwareIntrospectionAuthenticationProvider` plus `introspectionJwtDecoder`: signature/time, session, customer/delegation, and Agent route/workload/broker authority validators for locally decoded tokens | The tested isolated service returns inactive after root-session or route revoke. Validator authority-store exceptions reject validation. | Introspection caller-to-audience authorization is not established; the isolated sibling confidential client could introspect tokens it possessed for other audiences. A dependency outage response at the endpoint is not yet characterized. |
| Offline JWKS receiver | Outside Axiom's validator chain | Signature, issuer and expiry can be checked locally. | No current Axiom evidence shows that an offline receiver learns root-session, route, broker, workload, user-disable, or customer-grant revocation before expiry. Do not describe this as immediate revocation. |

## Freshness and cache position

The code paths above perform Axiom-side authority/session checks; this review does not establish a shared receiver cache, cache key, version token, invalidation channel, revocation SLO, outage budget or p95 latency target. Until those are designed and measured per route class, a receiver needing current revocation must use a verified revocation-aware boundary rather than assume that a valid JWT signature is enough. Argus context, run and branch identifiers remain Argus-owned and are not copied from caller-supplied input claims into Axiom exchange tokens (Phase 0.4 test).

The isolated H-4 and H-5 runs in `phase-0.2-working-baseline.md` and `phase-0.2-h5-gap-characterization.md` show Axiom introspection/exchange behavior, not downstream enforcement. H-5 confirmed a G-13 user-disable gap in the then-installed release. A later Axiom-only source change revokes affected sessions and checks live principal status, but has not been deployed or exercised as a two-transaction race; it is not a deployed freshness guarantee.

## Session-validation write load (Axiom-only source increment)

`IamSessionService.touch` now supplies a 30-second cutoff to a conditional repository update. A session touched more recently does not update `last_seen_at`; the update still requires the same tenant and `ACTIVE` status. Session validity, principal status and root-session checks remain on every applicable validation path. This bounds row-write amplification but does **not** remove the database round trip or prove millisecond latency. Java 25 focused service/validator/persistence tests exercise the cutoff and revoked-session case. The post-change full server suite passed **366 tests in 132 suites, 0 failures, 0 errors, 0 skipped**. Recovery is to remove the cutoff predicate/argument and restore the previous unconditional touch in this clone. No schema or deployment changed.

## Bounded outage regression and recovery

`SessionTokenValidatorTest.sessionStoreOutageFailsClosedWithoutTouchingSession` and `AgentExchangeTokenAuthorityValidatorTest.authorityStoreOutageFailsClosed` exercise exception paths for the local validators. On 2026-10-02, targeted Java 25 Surefire for both classes exited 0. These tests establish only local fail-closed validator results; they do not prove the endpoint status code, dependency outage behavior of every path, concurrency, cache fill, latency, or an external receiver.

No schema, token, route, or deployment was changed for this increment. Recovery is to revert only these tests and this baseline document if the contract is superseded; the original Axiom and Argus installations are unaffected.

## Not yet accepted

- Choose validation mode by recipient and route class, including which recipients may introspect which audiences and claims.
- Specify context lookup placement, authenticated binding, cache key/version, concurrent fill, invalidation and outage behavior jointly with the consuming runtime. Argus work is parked.
- Set and measure revocation staleness and latency budgets, then test stale state, concurrent cache fill, revocation and dependency outage end to end.
- Verify the Axiom-side user-disable source fix under a real two-transaction race and in the isolated release before claiming immediate disable semantics.

Phase 0.5 is **not Done** until those acceptance items have functional evidence; this source matrix and targeted tests are one Axiom-only package.
