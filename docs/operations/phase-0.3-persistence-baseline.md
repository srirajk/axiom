# Phase 0.3 — real persistence and migration baseline

Status: accepted for the **isolated Axiom test release** on 2026-10-02. This is not production equivalence or Argus receiver acceptance.

## Scope and dependencies

The test target was `docker-desktop`, namespace `axiom-phase0-test`, with the existing `postgres:16` and `redis:7-alpine` pods. The test runner connected only through localhost port-forwards to Services in that namespace. It used the test release's PostgreSQL credential without printing or retaining it. No pod, image, original database, original release, Argus component, or cluster-scoped resource was changed for this package. The test Axiom server remained Ready and used its separate `axiom-server:phase0-codex-74e7e56` image.

| Required behavior | Executable evidence | Result |
|---|---|---|
| Fresh PostgreSQL installation | `server/src/test/java/com/openwolf/iam/phase03/Phase03PersistenceIT.java`: create an exact random `p03_fresh_*` database, migrate from empty through V29, validate Flyway and the V29 active-route partial index | Pass |
| Supported adjacent upgrade | Same suite: create an exact random `p03_upgrade_*` database, migrate through V28, insert an existing tenant, upgrade to V29, validate Flyway/index and preserved tenant | Pass |
| Redis persistence connection | Same suite: `SETEX`, `GET`, `DEL`, and absent-after-delete for one random 60-second `phase03:*` key | Pass |
| Issuance and exchange against the isolated Axiom release backed by real PostgreSQL/Redis | Phase 0.2 H-1/H-2 harnesses: PKCE issuance, workforce/BFF exchange, broker/gateway/Agent/resource continuation and negative paths | H-1 5/5; H-2 15/15 |
| Revocation against that release | Phase 0.2 H-4: root-session revoke, all six descendant tokens inactive to Axiom introspection, further exchange denied. H-5/G-12: route revoke invalidates Axiom introspection/exchange; route-replacement recovery drill | H-4 24/24; G-12 20/20; recovery 23/23 |

The Java suite's source SHA-256 was `67f5ecb57e54898db738739579d278085b0d202c1e4fcfc186b8badb62876f5c` at execution. `mvn test-compile` exited 0. Targeted Maven Failsafe `integration-test` + `verify` exited 0; `target/failsafe-reports/com.openwolf.iam.phase03.Phase03PersistenceIT.txt` reports **3 tests, 0 failures, 0 errors, 0 skipped** (1.821 seconds). The two generated databases were absent from `pg_database` afterward; the `phase03:*` Redis scan returned no keys. Both port-forwards were stopped. The original `axiom` Helm release remained revision **2**, `deployed`.

## Recovery and limits

The suite creates only UUID-named `p03_*` databases and deletes each exact name in `finally`; its Redis key is UUID-named, TTL-limited to 60 seconds, and deleted in `finally`. If interrupted between creation and cleanup, inspect `pg_database` for `p03_%` and Redis for `phase03:*` **in `axiom-phase0-test` only** before removing any exact test-owned artifact. Do not drop the shared `axiom` database or remove the test release. This is a disposable-test cleanup procedure, not production backup/restore.

The upgrade test proves V28→V29 and the fresh test proves the current migration chain on PostgreSQL 16; it does not prove every historical upgrade combination or restoration from a production backup. Redis direct round-trip does not by itself prove every application cache path; the H-1–H-5 HTTP tests exercised the isolated Axiom service with its configured PostgreSQL/Redis dependencies. Existing G-02, G-07 and G-13 failures are characterized, **not fixed**. Original image provenance, original/Argus journey, offline receiver revocation, broker/workload revocation, network-policy enforcement through port-forward, and performance under load remain unproven. No later package should cite Phase 0.3 as resolving them.

Acceptance basis: the plan's fresh installation, adjacent supported upgrade, and issuance/exchange/revocation integration criteria are evidenced for the isolated baseline; test dependencies and cleanup/recovery were reviewed. Phase 0.4 may proceed without changing the original rollout.
