# Phase 0.2 — Axiom working baseline

Status: **accepted 2026-10-02 as a preservation baseline only**; not a production journey, original-image provenance, or offline-receiver acceptance. Recorded 2026-10-01 against clone `axiom-changes`, branch
`hardening/phase-0-baseline`, HEAD `74e7e56`. This document records evidence and procedures only.

- **Original approved rollout (§2–§11):** release `axiom` in namespace `axiom`. Only the read-only checks in §9
  were run against it. It remains at Helm revision 2.
- **Isolated test environment (§12):** a separate, test-only release `axiom` in namespace `axiom-phase0-test`,
  created by Codex on 2026-10-01 with user authorization. It is **not** the approved rollout, and its results
  are not evidence about the original installation. The Claude session made no changes in either namespace.

## 1. Evidence classes

| Tag | Meaning |
|---|---|
| **OBS-C** | Observed directly by the Claude session with a read-only command (listed in §9). |
| **OBS-X** | Observed by Codex with read-only database queries against the existing PostgreSQL pod (§9). |
| **TEST-X** | Action or observation by Codex in the isolated `axiom-phase0-test` namespace (§12). Evidence about the isolated test install only. |
| **TEST-C** | Read-only corroboration by the Claude session of the isolated `axiom-phase0-test` namespace (§12). |
| **SRC** | Present in source or configuration in this clone. Says what *would* happen, not what is deployed. |
| **CLAIM** | Stated in docs, commit messages or script "must end with" text. Not evidence of a passing run. |
| **UNKNOWN** | No evidence either way. |

## 2. Approved rollout metadata

| Item | Value | Class |
|---|---|---|
| Kube context | `docker-desktop`, namespace `axiom` | OBS-C |
| Helm release | `axiom`, revision **2**, status `deployed`, last deployed 2026-09-30 18:14:58 (local) | OBS-C |
| Helm revision 1 | 2026-09-30 17:56:29, superseded. Only values difference from rev 2: `config.corsAllowedOrigins` gained `http://localhost:5180` | OBS-C |
| Chart | `axiom-0.1.3`, appVersion `1.0.0` | OBS-C |
| Chart source comparison | Rendering this clone's `deploy/helm/axiom` with the rev 2 user values produced the same set of lines as the deployed rev 2 manifest plus hooks in a preliminary order-insensitive comparison. This is **not** a structural manifest equivalence check. Deployed manifest sha256 `1c5ecbb0…0feba` | OBS-C, limited |
| Values source match | Deployed user values equal this clone's `deploy/kind/values.yaml` except `config.corsAllowedOrigins` (deployed adds `http://localhost:5180`) | OBS-C |
| Server image | `axiom-server:local-quickstart-rfc8693`, digest `sha256:8de08a945aa3277d3f4f9c83e25625df25ec29a7bf38d2a65455ec9ab4de55ee`, built 2026-09-30T04:39:42Z, `imagePullPolicy: IfNotPresent`, pod annotation `axiom.meridian.com/build: quickstart-rfc8693`. Both Helm revisions (ReplicaSets `axiom-bf5c54894` rev 1, `axiom-569c79c86f` rev 2) use this tag | OBS-C |
| **Image source commit** | **UNKNOWN.** The image carries no git-revision label. It was built six days after HEAD `74e7e56` (2026-09-24) and may include uncommitted changes from the original checkout. | UNKNOWN |
| Admin image | `axiom-admin:local`, `sha256:92056c0f4611a085b19057057e9bff1ed86756455fb8371b58495a892df2e4c5` | OBS-C |
| Cerbos | `ghcr.io/cerbos/cerbos:0.53.0`, `sha256:c3fe64202e3793b7e9c41c5cbfcf390a51fb28ebce0a7d70754155e70db839c4` | OBS-C |
| PostgreSQL | StatefulSet `axiom-postgresql`, image tag `postgres:16` (not digest-pinned in manifest), running `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54` | OBS-C |
| Redis | StatefulSet `axiom-redis`, tag `redis:7-alpine`, running `sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499`. No password key in the runtime Secret | OBS-C |
| Replicas | 1 server, 1 admin, 1 Cerbos, 1 Postgres, 1 Redis; all on node `desktop-worker` | OBS-C |
| Helm test | `axiom-smoke` Succeeded, exit 0, finished 2026-09-30T22:16:34Z | OBS-C |

### Relevant non-secret values (rev 2)

| Key | Value |
|---|---|
| `config.issuerUrl` | `https://identity.meridian.com:8443` |
| `config.adminPublicUrl` | `https://identity-admin.meridian.com:8443` |
| `config.approvedBusinessScopes` | `cards:incident.read,cards:freeze.propose,wealth:review.invoke,quickstart:invoke` |
| `config.ciam.localDemoChallengeDisclosure` | `true` (demo setting) |
| `config.ciam.customerClientId` / `tenantId` | `card-customer-web` / `meridian` |
| `config.corsAllowedOrigins` | `https://identity-admin.meridian.com:8443,http://localhost:5182,http://localhost:5180` |
| `bootstrap.tenant` | `meridian` / `Meridian Bank` |
| `postgresql.database` / `redis.database` | `axiom_quickstart` / `1` |
| `policyRuntime.backend` | `pvc` (`axiom-policy-runtime`) |
| `nodeSelector` | `kubernetes.io/hostname: desktop-worker` |

Secrets present (names and key counts only, values not read): `axiom-runtime` (3 keys), `axiom-signing-key` (2 keys).

### Storage

| PVC | Size | PV reclaim policy | Class |
|---|---|---|---|
| `data-axiom-postgresql-0` | 4Gi | **Delete** | OBS-C |
| `data-axiom-redis-0` | 1Gi | **Delete** | OBS-C |
| `axiom-policy-runtime` | 1Gi | **Delete** | OBS-C |
| `axiom-cerbos-audit` | 1Gi | **Delete** | OBS-C |

The StatefulSets retain PVCs when the StatefulSet is deleted (`whenDeleted: Retain`). Deleting a PVC deletes its data.

### Network and edge

| Item | Value | Class |
|---|---|---|
| HTTPRoutes (`gateway-demo`) | `axiom-identity-https` → `axiom/axiom`, `axiom-admin-https` → `axiom/axiom-admin`; HTTP routes have no backend (redirect) | OBS-C |
| NetworkPolicies in `axiom` not managed by the Axiom chart | `default-deny`, `allow-dns`, `allow-axiom-dependencies`, `allow-*-from-axiom`, `allow-gateway-and-clients`; plus `quickstart-mcp-next-to-axiom`, `quickstart-mcp-to-axiom`, `quickstart-python-agent-to-axiom`, `quickstart-task-to-axiom`, `quickstart-worker-to-axiom` (no manager label); `quickstart-to-axiom` is managed by Helm release `argus-quickstart` | OBS-C |

## 3. Deployed database state

All values in this section are **OBS-X** (Codex, read-only, existing `axiom-postgresql-0` pod), 2026-10-01.

| Item | Value |
|---|---|
| Application database | `axiom_quickstart` (the `axiom` database is empty) |
| Public tables | 42 |
| Flyway | Successful through **V29** |
| Active tenants | 1 |
| OAuth registered clients | 15 |
| Tenant applications / application clients | 12 / 14 |
| Active Agent workload identities | 11 |
| Active trusted exchange brokers | 1 |
| Active exchange routes | **30** — 10 AGENT, 10 GATEWAY, 10 RESOURCE; none expired |
| Route expiry range | **2026-10-30 to 2026-10-31** |
| Customer delegation grants | 0 |

## 4. Source-versus-deployed configuration drift (G-35)

| Object | Clone `configuration/tenants/meridian/ciam` (SRC) | Deployed (OBS-X) | Difference |
|---|---|---|---|
| Applications | 25 | 12 | 11 shared; 14 source-only, 1 deployed-only |
| Agent workloads | 18 | 11 active | 8 shared; 10 source-only, 3 deployed-only |
| Trusted brokers | 1 | 1 active | Same client, audience, and allowed-scope set |
| Exchange routes | 42 (all `ttlSeconds: 2592000`) | 30 active | 18 shared; 24 source-only, 12 deployed-only |
| Public clients | 5 | 2 deployed public clients | 1 shared; 4 source-only, 1 deployed-only |

The 14 source-only applications include `card-assistance`, `card-actions`, `card-incident-records`, and 11 `wealth-*` applications. The deployed-only application is `conduit`. Ten source-only workloads are the card/wealth workloads; the three deployed-only workloads are `service:quickstart-authoring-service:development`, `service:quickstart-journey-step5-gateway-service:development`, and `service:quickstart-rebuild-authoring-service:development`. The 24 source-only routes are card/wealth routes; the 12 deployed-only routes are four for each deployed-only service workload. The shared 18 quickstart routes match on source, destination type, destination/audience, allowed-scope set, purpose, and TTL. Shared application audiences and workload client IDs also match. The deployed-only public client is `conduit-console`; the shared one is `quickstart-human-web`.

**Conclusion:** the clone's configuration does not describe the complete deployed authority state and cannot be replayed as a recovery source as-is. Record-level comparison narrows the difference to missing card/wealth source records and deployed-only conduit/quickstart service records, not unexplained drift in the shared route authority fields. The configuration that created the deployed-only records, client details beyond those listed above, and whether any source-only records existed previously in a revoked state remain unverified. See §8.1.

## 5. Working flows: evidence versus claims

| Flow | Status | Basis |
|---|---|---|
| Axiom pods serving | **Evidenced** | All pods Running, 0 restarts for ~25h (OBS-C) |
| Readiness UP, OIDC discovery shows issuer, admin UI and runtime config served | **Evidenced** at 2026-09-30T22:16:34Z | `axiom-smoke` Helm test Succeeded (OBS-C); this is not an issuance, exchange, or receiver test |
| Schema at V29; identities and routes provisioned and active | **Evidenced** | OBS-X counts |
| Chart and values reproduce from this clone | **Preliminary evidence** (chart and values only, not image) | OBS-C line-set render comparison, not structural parity |
| Fresh isolated install from this clone's chart (`axiom-phase0-test`) | **Evidenced for the isolated test install only** | All components Ready; `helm test` passed; fresh database Flyway at V29 (TEST-X, partly TEST-C, §12). Says nothing about the original image, the original database, or any journey |
| Workload issuance, one autonomous workload → test-gateway exchange, and wrong-audience / wrong-redeemer / over-broad-scope denials (H-1) | **Evidenced for the isolated test install only** | One Codex run of the reviewed harness, all 5 cases passed, exit 0 (TEST-X, §12.7). No human, BFF, Argus, Agent-to-Agent, resource, revocation or receiver behaviour |
| Axiom token chain: human PKCE → workforce → BFF → test gateway → Agent → test gateway → resource, plus 9 denials (H-2) | **Evidenced for the isolated test install only, as Axiom-issued tokens** | One Codex run of the reviewed harness, all 15 cases passed, exit 0 (TEST-X, §12.8). No real Argus Gateway, no receiver enforcement, no production equivalence, no revocation |
| Local server regression suite | **Evidenced in the clone** | `JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home mvn -q test` exited 0 after test-fixture repairs (§9). This uses local H2/Testcontainers/Cerbos; it does not prove the installed image or deployed journey. |
| Workforce PKCE → BFF → Gateway → Agent → tool chain | **CLAIM** | `scripts/verify-quickstart-human-exchange.py`, `scripts/verify-quickstart-agent-exchange.py`; commit messages `8788592`, `2565795`, `71d0dd0`, `25954a5`. No recorded run output in the repo |
| Argus Gateway exchange chain and negative cases | **CLAIM** | `scripts/verify-argus-agent-exchange.py`; `docs/operations/control-plane-axiom-integration.md:110-113` ("must end with") |
| Wealth fan-out | **CLAIM** | `scripts/verify-wealth-agent-exchange.py`; `docs/operations/ciam-agent-delegation-acceptance.md:141-160` |
| Public PKCE session lifecycle | **CLAIM** | `scripts/verify-public-pkce-session-lifecycle.py` |
| CIAM customer delegation | **Not exercised in this environment** | 0 delegation grants (OBS-X) |
| Root-session revocation of already-issued tokens | **Evidenced for Axiom introspection and exchange in the isolated install only** | H-4 (TEST-X, §12.10). Offline JWKS receiver behavior and other revocation classes remain unproven |

## 6. Dependencies for subsequent tool, Agent and BFF work

From clone configuration (SRC), with deployed presence and shared-field comparisons noted in §4 and §8.1.

| Dependency | What depends on it | Breaks if changed |
|---|---|---|
| Issuer `https://identity.meridian.com:8443` and its signing key (`axiom-signing-key`, `signing_keys` table) | Every relying party, including Argus local JWT validation with projected JWKS | Issuer mismatch or loss of the verifying key breaks validation; normal key rotation can retain a verification overlap |
| Broker `argus-gateway-broker`, audience `argus-gateway`, scopes `cards:incident.read, wealth:review.invoke, quickstart:invoke` | All Gateway → Agent/resource exchanges | Broker revoke or scope change stops all gateway-backend exchanges |
| `approvedBusinessScopes` value | Client and route scope validation | Removing `quickstart:invoke` or `wealth:review.invoke` breaks those journeys |
| Quickstart workloads: `quickstart-entry`, `quickstart-agent`, `quickstart-service`, `quickstart-worker-agent`, `quickstart-task-agent`, `quickstart-python-agent`, `quickstart-bff`, `quickstart-wrong-audience` (negative test) | Tool, Agent, MCP and BFF steps | Workload revoke stops that hop |
| Quickstart routes (SRC): entry → GATEWAY, entry → AGENT quickstart-agent, entry → RESOURCE tool, entry → AGENT python-agent; agent → GATEWAY, agent → RESOURCE tool and MCP, agent → AGENT worker; service → GATEWAY, service → AGENT agent and task-agent; worker → GATEWAY, worker → AGENT task-agent; task-agent → GATEWAY and RESOURCE tool; python-agent → GATEWAY; BFF → GATEWAY and BFF → AGENT entry | Each corresponding token-exchange hop | Expiry 2026-10-30/31 (§7) stops active deployed routes; the 18 shared quickstart routes match the compared source authority fields (§4) |
| Human entry: public client `quickstart-human-web` and workload `quickstart-bff` under application `quickstart-workforce`; membership `quickstart_user` → role `quickstart-operator` | BFF path (Phase 1.10) | G-07: the source app is not checked at exchange; correctness currently relies on both clients sharing one application |
| Workload credentials in Kubernetes Secrets in `quickstart`, `wealth` and `argus-system` (names in `agent-workloads.jsonl`, `trusted-brokers.jsonl`) | Each workload's client authentication | Client secret rotation is immediate, with no overlap |
| NetworkPolicies `quickstart-*-to-axiom` in `axiom` | Quickstart workloads reaching Axiom | Removal blocks token calls; five have no manager label, so their owner is UNKNOWN |
| Redis database 1 | OAuth authorizations, authorization codes, PKCE flow state | Loss forces re-login and breaks in-flight flows; it does not grant authority |
| Operator automation (`scripts/configure_axiom.py`) | Any configuration change, including route re-publication | Requires `/auth/login` (Phase 0.6) |

## 7. Route re-publication — EXTERNALLY MANAGED (not verified)

Facts:

- All 30 active routes expire **2026-10-30 to 2026-10-31** (OBS-X). After that, every exchange in §6 fails closed.
- No renew or extend API exists. The route endpoints are `POST /routes`, `GET /routes`, `POST /routes/{id}/revoke` (`server/src/main/java/com/openwolf/iam/controller/AgentExchangeAuthorityController.java:56-69`). Maximum lifetime is 90 days (`AgentExchangeAuthorityService.java:144-145`).
- `scripts/configure_axiom.py:622-669` does **not** renew. If an active route has `expiresAt <= now`, it raises `Agent exchange route drift` and stops. Before expiry, it leaves the route unchanged.
- Route creation has no service-level duplicate-active check, but migration V29 defines `uq_active_exchange_route` on `(tenant_id, source_workload_id, destination_type, audience)` where `status = 'ACTIVE'`. An identical replacement is rejected by PostgreSQL while the prior row remains ACTIVE, **even after `expires_at`**. Codex confirmed the installed index definition in the deployed database (OBS-X).
- Revoking then recreating a route changes its ID and authority reference. Existing exchanged tokens may no longer support continuation; a procedure must cover fresh token acquisition and the interruption window.
- Re-running `configure_axiom.py` from this clone would attempt to create source-only card/wealth records and would not reconstruct the deployed-only conduit/quickstart service records (§4). It is not a safe renewal or recovery operation as-is.

Ownership: **externally managed by the user.** The user has stated they will handle route renewal later. This
package does not verify the renewal method, its timing or its outcome, and it neither plans nor performs it. The
facts above are recorded for whoever performs the renewal. Points they may want to consider (informational, not
open decisions of this package):

- Revoke-then-recreate gives each route a new ID and authority reference, with an interruption window and fresh-token acquisition.
- A replay from this clone's configuration is unsafe until §4 is reconciled.
- The current expiry is 2026-10-30/31.

No live route was read beyond the Codex aggregate (§3), and no route was changed. This item is not re-raised in later packages.

## 8. Unresolved items

### 8.1 Name-level reconciliation — scoped read-only evidence

Codex read only non-secret authority fields in `axiom_quickstart`, restricted to tenant `meridian`, and compared them with the source JSONL files. The result is summarized in §4; no database record was changed. The queried fields were:

| Table | Columns |
|---|---|
| `tenant_applications` | `application_key`, `audience`, `status`, `revision` |
| `tenant_application_clients` joined to `tenant_applications` | `client_id`, `client_type`, `status`, `application_key`, `allowed_scopes`, `revision` |
| `oauth2_registered_client` | `client_id` only |
| `agent_workload_identities` | `workload_ref`, `oauth_client_id`, `status`, `revision` |
| `trusted_exchange_brokers` | `oauth_client_id`, `gateway_audience`, `allowed_scopes`, `status`, `revision` |
| `agent_exchange_routes` joined to `agent_workload_identities` (source and destination) | route `id`, source `workload_ref`, `destination_type`, destination `workload_ref`, `audience`, `allowed_scopes`, `purpose`, `status`, `expires_at`, `revision` |
| PostgreSQL catalog for `uq_active_exchange_route` | installed index definition, to confirm V29's source constraint is deployed |

Exclude client secrets, password hashes, private keys, token values, emails and customer data.

The installed `uq_active_exchange_route` index is a unique partial index over `(tenant_id, source_workload_id, destination_type, audience)` with predicate `status = 'ACTIVE'` (OBS-X). Shared quickstart route scopes, purpose, and TTL match source; shared applications' audiences and workloads' client IDs match source. This is a scoped authority comparison, **not** proof that the running image was built from this clone or that a full business journey works. A later recovery package must identify the owner/source of the deployed-only records and compare any additional client attributes it relies on before replaying configuration.

### 8.2 Other open items

| Item | Status |
|---|---|
| Image-to-commit mapping (original rollout) | UNKNOWN. Needs the build record, or a future image built with a git-revision label. The isolated test images (§12) do not resolve this |
| Isolated test image provenance | Server image built by Codex from this clone (TEST-X claim); no git-revision label (TEST-C). The isolated **admin** image is a retag of the original `axiom-admin:local` (identical digest, TEST-C), so its source commit is also UNKNOWN |
| Full BFF → Gateway → Agent → tool journey | **Axiom token chain evidenced in the isolated install only** (H-2, §12.8). The end-to-end journey through the real Argus Gateway and receivers, in the original rollout, is NOT PROVEN (§12.8.3) |
| Owner of the five unmanaged `quickstart-*-to-axiom` NetworkPolicies | UNKNOWN |
| Whether the original checkout's uncommitted `configuration/operator-demos/` and scripts produced the deployed-only conduit/quickstart state | UNKNOWN; possible explanation for part of G-35 |
| Journey execution evidence | CLAIM only (§5) |
| Deployed end-to-end journey execution | NOT RUN in this package. Existing scripts read live client secrets and issue tokens; running them against the current installation requires a separate reviewed test window or isolated environment. |
| Route re-publication | Externally managed by the user; not verified (§7) |
| **G-36 security gap: `POST /users` overwrites an existing principal** | **OPEN.** Confirmed in source during H-2 contract work. `UserService.createUser` checks only that the username is unused, then `save()`s `new Principal(req.id(), …)`. `Principal` has an assigned `@Id`, no `@Version` and no `Persistable`, so JPA merges onto any existing principal with that id (`server/src/main/java/com/openwolf/iam/service/UserService.java:91-110`, `entity/Principal.java:34-36`). A `tenant_admin` or `domain_admin` (allowed on `POST /users`, `SecurityConfig.java:432`) could replace another principal's username, password hash and tenant, for example the bootstrap `admin`. Audit is best-effort. Not fixed in any H package: the harnesses only work around it (H-2 checks `GET /users/{id}` returns 404 before creating). A separate fix task has been proposed; ownership and scheduling are open. |

## 9. Read-only checks performed in this package

```text
git rev-parse --show-toplevel; git branch --show-current; git status --porcelain
helm status axiom -n axiom
helm history axiom -n axiom
helm get values axiom -n axiom --revision 1|2 -o yaml
helm get manifest axiom -n axiom --revision 2
helm get hooks axiom -n axiom --revision 2
helm template axiom deploy/helm/axiom -n axiom -f <rev2 values>   (local render, compared order-insensitively)
kubectl rollout history deploy/axiom -n axiom
kubectl get rs|deploy|sts|pvc|pv|networkpolicy -n axiom (selected columns)
kubectl get pod axiom-smoke -n axiom (phase, exit code, finish time)
kubectl get httproute -n gateway-demo (names, hosts, backends)
docker image ls --digests axiom-server
grep/sed reads of scripts/configure_axiom.py and AgentExchangeAuthorityService/Controller in the clone
kubectl exec -n axiom axiom-postgresql-0 -- env PGOPTIONS='-c default_transaction_read_only=on' psql -U axiom -d axiom_quickstart -c '<tenant-scoped SELECT>'
kubectl exec -n axiom axiom-postgresql-0 -- env PGOPTIONS='-c default_transaction_read_only=on' psql -U axiom -d axiom_quickstart -c '<SELECT pg_get_indexdef(...) for uq_active_exchange_route>'
local comparison of non-secret JSONL identifiers and authority fields against those SELECT results
JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home mvn -q test (local clone; final run exited 0)
```

The Helm/Kubernetes inventory above was performed by Claude (OBS-C); the database SELECTs and source comparison were performed by Codex (OBS-X). The SQL session enforced `default_transaction_read_only=on`. Not performed against the original `axiom` namespace or Argus: Secret value reads, journey scripts, Argus reads, any cluster mutation.

Cluster mutations **did** occur, but only in the isolated namespace `axiom-phase0-test`, performed by Codex (§12). The Claude session ran only read-only commands there (§12.6).

The first local Maven attempt used the shell's Java 21 and could not compile the project's Java 25 target. With Java 25, the initial 348-test run had 2 failures and 46 errors. The errors were MVC slice fixtures missing Redis and SCIM filter dependencies; one failure was a Base64 tamper test that could alter only unused encoding bits; the other was an in-memory promotion repository fixture that did not implement the conditional failure update. Codex repaired those **test-only** fixtures in this clone and the final full Maven run exited 0. These local fixture changes do not alter deployed behavior. If they must be rolled back, revert those test-file edits in this isolated branch; no cluster or data rollback is needed.

## 10. Recovery and rollback procedures (documented, NOT executed)

### 10.1 Before any future change to this environment

1. Record `helm get values|manifest|hooks axiom -n axiom --revision 2` (as in §9) and compare against §2.
2. Confirm the node still holds the server image digest `sha256:8de08a94…`. The tag `local-quickstart-rfc8693` is mutable and `imagePullPolicy` is `IfNotPresent`, so a retag would silently change what a rollback runs. Preserve the image, for example:

   ```bash
   docker save axiom-server:local-quickstart-rfc8693 -o axiom-server-rfc8693.tar
   ```

3. Take a logical database backup of `axiom_quickstart` (for example `pg_dump -Fc` from the existing pod to an operator-held location). PVs use reclaim policy **Delete**.
4. Confirm `axiom-runtime` and `axiom-signing-key` exist and are backed up by their operator. Helm does not own or restore them.
5. Redis state is treated as reconstructible. Loss forces re-login; take a snapshot only if in-flight sessions matter.

### 10.2 Restoring Helm revision 2

```bash
helm rollback axiom 2 -n axiom --wait --timeout 15m
```

```bash
helm test axiom -n axiom --logs --timeout 5m
```

Caveats:

- The rollback creates a new revision with the rev 2 manifests. The chart's `preflight`, `bootstrap` and `verify` hooks are `pre-install`/`pre-upgrade`/`post-install`/`post-upgrade` only, so they do **not** run on rollback. Run `helm test` afterwards.
- It does **not** roll back the database. Flyway is forward-only. If a later release applied V30+, the rev 2 image must still start against that schema: expand-only migrations are required (Phase 4.3). Otherwise restore the §10.1 database backup — note this would also restore any revoked authority (Phase 4.10).
- It does not restore Secrets, Redis, routes or other configuration records.
- If the image tag was retagged, use an upgrade pinned to the digest instead of a rollback:

  ```bash
  helm upgrade axiom deploy/helm/axiom -n axiom -f <rev2 values> --set server.image.digest=sha256:8de08a945aa3277d3f4f9c83e25625df25ec29a7bf38d2a65455ec9ab4de55ee --wait --timeout 15m
  ```

  This runs the pre-upgrade hooks, including `bootstrap`, against the existing database.

### 10.3 Data and configuration recovery

| Failure | Recovery |
|---|---|
| Database loss or corruption | Restore the §10.1 dump into `axiom_quickstart`. Then reconcile revocations made after the backup (Phase 4.10). |
| Route expiry | Externally managed by the user (§7); not verified here. |
| Accidental route revoke | **Stop and escalate for the original rollout.** There is no un-revoke. A TEST-X drill (§12.11) showed a new route with a new authority ID can issue a new active token while the old token remains inactive. For the original rollout, first identify the route owner and all dependents, review an equivalent replacement route and its expiry/scopes, publish it through the approved operator path, have callers reacquire tokens, verify new/old token states and audit, then remove any superseded route. This is not a proven original-rollout runbook or an automatic renewal procedure. |
| Accidental broker or workload revoke | **Stop and escalate.** Registration rejects the same broker client/audience and the same workload reference/client even when the old row is revoked. Replacement requires a new identity, dependent-route and client updates, and a separately reviewed migration/recovery procedure. Do not simply re-run the configuration script. |
| Signing-key change | **Stop and use the approved key-lifecycle runbook.** The API activates only STAGED keys; it cannot reactivate a previous VERIFICATION_ONLY or RETIRED key. Normal rotation retains the previous public key for a bounded verification overlap, so a key change does not automatically invalidate every existing token. Reconcile `kid`, signing state, and JWKS caches before traffic resumes. |
| Redis loss | Users and workloads re-authenticate; no restore. |

## 11. Acceptance checklist for Codex review

- [x] Root and branch verified before writing; existing uncommitted Codex changes (test fixtures, `deploy/phase0-isolated/`, this document) preserved (§9).
- [x] Helm release, revision, chart, values and image digest recorded (§2).
- [x] Image source commit recorded as UNKNOWN, not inferred (§2).
- [x] Codex database observations recorded with their source and date (§3).
- [x] Route expiry dates recorded (§3, §7).
- [x] G-35 drift recorded with record-level names, shared authority-field comparison, and conclusion (§4, §8.1).
- [x] Working flows separated into evidenced vs claimed (§5).
- [x] Local Java 25 suite passes after test-fixture repairs; deployed journey remains a separate acceptance gate (§5, §9).
- [x] Dependencies for tool, Agent and BFF work mapped (§6).
- [x] Route re-publication recorded as externally managed by the user and not verified, with no route changed (§7).
- [x] Name-level identifiers reconciled by Codex, excluding secrets and personal data (§8.1).
- [x] Recovery and Helm rollback documented with caveats, not executed (§10).
- [x] Isolated test environment recorded separately from the original rollout, with its limits (§12).
- [x] Isolated-environment teardown and data-loss caveats documented, not executed (§12.4–§12.5).
- [x] No production code or configuration changed; no change to the original `axiom` release or namespace, or to Argus; cluster changes confined to `axiom-phase0-test` (Codex); no commit, merge or push.
- [x] Open gaps preserved:
  - original image provenance;
  - source/config drift (G-35);
  - the real BFF → Argus Gateway → Agent → receiver journey and the original rollout, not proven. Only the Axiom-issued token chain is evidenced, in the isolated install (§12.8);
  - route revocation is proven only at Axiom introspection/exchange in TEST-X; broker/workload revocation and offline JWT receiver enforcement remain unproven (§12.11);
  - G-13 user disable leaves TEST-X sessions and previously issued tokens active; an immediate-revoke design and fix remain open (§12.11);
  - route renewal externally managed and unverified;
  - the `POST /users` overwrite security gap G-36 open (§8.2).
- [x] Isolated H-1 functional evidence recorded as TEST-X, with its limits; the §12.7.3 gap table is updated to current status (§12.7).
- [x] Isolated H-2 Axiom token-chain evidence recorded as TEST-X, distinguished from Argus Gateway/receiver enforcement, production equivalence and revocation (§12.8).
- [x] Isolated H-3 introspection and tamper evidence recorded as TEST-X, including the first failed harness assertion and corrected rerun; no revocation or Argus enforcement claim (§12.9).
- [x] Isolated H-4 root-session revocation and `subject_sid` propagation recorded as TEST-X, without claiming offline receiver enforcement or all revocation classes (§12.10).
- [x] Isolated H-5/G-02, G-07, G-12-route and G-13 behavior recorded as TEST-X, including cleanup, open fixes and receiver limitations (§12.11).

**Codex acceptance, 2026-10-02:** Phase 0.2 is accepted as the record and preservation of the existing rollout, **not** as proof that the original BFF → Argus Gateway → Agent → receiver journey works. The original release was read-only rechecked at revision 2 `deployed`, its server 1/1 Ready, and the previously completed `axiom-smoke` pod remained `Succeeded`/exit 0. No original workload, route, Secret or deployment was changed. The isolated Axiom token chain, negative tests and route-replacement drill have their own TEST-X evidence and cleanup; they cannot establish original-image equivalence. Recovery and rollback are documented with explicit hazards but were not performed on the original rollout. The source/image provenance, G-35 deployed-only configuration ownership, G-36 principal overwrite, G-02/G-07/G-13 fixes, original end-to-end/receiver enforcement, offline revocation, and route renewal remain open gates in the later phases; this acceptance does not waive them.

**Later G-36 source increment, 2026-10-02 (not deployed):** `UserService.createUser` now checks the globally keyed principal ID before the username check and uses `EntityManager.persist` rather than `JpaRepository.save`. This prevents an assigned-ID JPA merge from replacing a principal, including one in another tenant; a concurrent duplicate insert is rejected by the primary key rather than overwriting. `UserServiceCreateUserSafetyTest` checks duplicate-ID denial and insert-only creation (2/2); the post-change Java 25 server suite passed 357 tests with zero failures, errors or skips. This has not been tested through a deployed endpoint or under concurrent HTTP requests, and does not retroactively change the Phase 0.2 installed observation. Recovery is to revert the bounded `UserService` and test changes in this clone, then rerun focused/full tests; no schema migration or original-release change was made.

## 12. Isolated test environment `axiom-phase0-test` (separate from the approved rollout)

### 12.1 Purpose and boundary

A disposable, test-only install of this clone's chart, used to establish a fresh baseline without touching the
original `axiom` release. It shares the Docker Desktop cluster, node `desktop-worker` and local image store with
the original. It shares no namespace, Secret, PVC, PV, Service, database or Redis with it.

### 12.2 Evidence

| Item | Value | Class |
|---|---|---|
| Authorization | User-authorized test namespace | TEST-X |
| Namespace | `axiom-phase0-test`, Pod Security `restricted` (enforce, audit, warn) | TEST-C |
| Helm release | `axiom` revision 1, chart `axiom-0.1.3`, `deployed`, 2026-10-01 20:45:27 (local) | TEST-C |
| Values | `deploy/phase0-isolated/values.yaml` (uncommitted, in this clone). Issuer `http://axiom.axiom-phase0-test.svc.cluster.local:8084`; database `axiom`, Redis database 0; `localDemoChallengeDisclosure: false`; test tenant `meridian` ("Meridian Phase 0 Isolated Test"); admin email `admin@phase0.invalid` | SRC |
| Dependencies | Postgres, Redis and Cerbos from `deploy/kind/dependencies.yaml` via `deploy/phase0-isolated/kustomization.yaml`, re-namespaced to `axiom-phase0-test`. Building it needs `--load-restrictor LoadRestrictionsNone`, because it references `../kind/dependencies.yaml`; with that flag, the only Namespace object it renders is `axiom-phase0-test` | TEST-C (local render) |
| Server image | `axiom-server:phase0-codex-74e7e56`, `sha256:42e702bffa8ebf863f976587297a32914eb76bd1382df78fcd90c5630740903f`, created 2026-10-02T00:33:52Z. Built by Codex from this clone (TEST-X claim). **No git-revision label** | TEST-C / TEST-X |
| Admin image | `axiom-admin:phase0-codex-74e7e56` has the **same digest** as the original `axiom-admin:local` (`sha256:92056c0f…`), created 2026-09-30. It is a retag, not a rebuild from this clone; its source commit is UNKNOWN | TEST-C |
| Cerbos, Postgres, Redis images | Same digests as the original rollout (§2) | TEST-C |
| Readiness | Deployments `axiom`, `axiom-admin`, `axiom-cerbos` 1/1; StatefulSets `axiom-postgresql`, `axiom-redis` 1/1; 0 restarts | TEST-C |
| Helm test | `axiom-smoke` Succeeded, exit 0, finished 2026-10-02T00:46:17Z | TEST-C |
| Database | Fresh database; Flyway at **V29** | TEST-X (not re-read by Claude) |
| Guardrails | `default-deny` NetworkPolicy (created before workloads) plus 6 allow policies. `allow-gateway-and-clients` is patched to admit only `axiom-phase0-probe` pods and Axiom's own pods, with no cross-namespace ingress. ResourceQuota `phase0-quota`: `services.nodeports: 0`, `services.loadbalancers: 0`, 12 pods, 5 PVCs, 10Gi storage. LimitRange `phase0-limits` | TEST-C |
| Exposure | All 5 Services are ClusterIP; no HTTPRoute or Gateway attachment | TEST-C |
| Secrets | `axiom-runtime` (3 keys), `axiom-signing-key` (2 keys), Helm release record. Values not read. Generated for this namespace only | TEST-C (names only) |
| Storage | 4 PVCs (`data-axiom-postgresql-0` 4Gi, `data-axiom-redis-0` 1Gi, `axiom-policy-runtime` 1Gi, `axiom-cerbos-audit` 1Gi). Their PVs (`pvc-56965387…`, `pvc-f180d5b0…`, `pvc-50927f92…`, `pvc-207145ac…`) have reclaim policy **Delete** | TEST-C |
| Probe and canary manifests | `deploy/phase0-isolated/image-probe.yaml` and `network-canary.yaml` exist in the clone; no such pods were running at the time of the check | TEST-C |
| Original rollout unaffected | `helm history axiom -n axiom` still ends at revision 2 `deployed` | TEST-C |

### 12.3 What this proves and what it does not

Proves, for the isolated install only:

- this clone's chart installs cleanly on a fresh namespace with the test values;
- a fresh database migrates to V29 with this server image;
- readiness, OIDC discovery and the admin UI respond (the Helm smoke test).

Does **not** prove:

- the provenance of the original `axiom-server:local-quickstart-rfc8693` image (still UNKNOWN);
- that the isolated server image matches the original image's behaviour;
- anything about the original database, its identities or its routes;
- any issuance or exchange behaviour beyond the bounded H-1 (§12.7) and H-2 (§12.8) cases, and any revocation, introspection or receiver behaviour;
- the full BFF → Gateway → Agent → tool journey (still NOT PROVEN anywhere);
- a resolution of the G-35 source/config drift (§4), or anything about route renewal, which is externally managed (§7).

### 12.4 Safe teardown (documented, NOT executed)

Run only after Codex or the user approves teardown. Every command names `axiom-phase0-test` explicitly. The
current kube context has no default namespace, so commands without `-n` would target `default`.

1. Preconditions. Stop if any check fails.

   ```bash
   kubectl config current-context
   ```

   Expect `docker-desktop`.

   ```bash
   helm list -n axiom-phase0-test
   ```

   Expect exactly one release, `axiom`, chart `axiom-0.1.3`.

   ```bash
   helm history axiom -n axiom
   ```

   Record it. It must still end at revision 2; compare it again after teardown.

2. Capture any evidence still wanted before deletion, such as `helm test` logs or the Flyway history. Teardown destroys it.

3. Uninstall the test release:

   ```bash
   helm uninstall axiom -n axiom-phase0-test --wait --timeout 5m
   ```

4. Remove the leftover Helm test pod, if present:

   ```bash
   kubectl delete pod axiom-smoke -n axiom-phase0-test --ignore-not-found
   ```

5. Delete the namespace. This removes the kustomize-applied Postgres, Redis, Cerbos, PVCs, NetworkPolicies, quota, LimitRange and Secrets.

   ```bash
   kubectl delete namespace axiom-phase0-test --wait=true --timeout=5m
   ```

6. Verify. Expect `NotFound`:

   ```bash
   kubectl get namespace axiom-phase0-test
   ```

   Expect no output, once the PVs have been reclaimed:

   ```bash
   kubectl get pv -o custom-columns=PV:.metadata.name,NS:.spec.claimRef.namespace | grep axiom-phase0-test
   ```

   Must be unchanged from step 1:

   ```bash
   helm history axiom -n axiom
   ```

7. Optional local image cleanup, by tag only:

   ```bash
   docker image rm axiom-server:phase0-codex-74e7e56 axiom-admin:phase0-codex-74e7e56
   ```

   Removing the admin tag only untags it, because the same image is still tagged `axiom-admin:local`.

Never do the following:

- run any teardown command against namespace `axiom`;
- run `helm uninstall axiom` without `-n axiom-phase0-test`;
- run `kubectl delete -k deploy/phase0-isolated` without first rendering it and confirming its targets;
- remove images by digest, or run `docker image prune -a`. Digest `sha256:92056c0f…` is the original rollout's running admin image, and pruning could remove images the original release needs on restart.

### 12.5 Data-loss caveats (isolated namespace only)

- The PV reclaim policy is **Delete**, so deleting the namespace permanently destroys the test PostgreSQL data (fresh V29 database, bootstrap tenant and administrator, test signing-key records), Redis state, the Cerbos policy runtime and the Cerbos audit volume. No backup is planned.
- The namespace's `axiom-runtime` and `axiom-signing-key` Secrets are destroyed. Any token issued by the test issuer becomes unverifiable. This is acceptable because the issuer is cluster-internal and test-only.
- No data is shared with the original `axiom` namespace, so teardown cannot remove original data, provided the namespace and image rules in §12.4 are followed.
- Recreating the environment produces new Secrets, a new signing key and a fresh database. Results from a recreated environment are not continuous with this one.
- The test database now also holds:
  - the H-1 records for prefix `p0hbf0a27cb52` (§12.7);
  - the H-2 records for prefix `p0h4c5e00bfb3` (§12.8). These are applications, clients, workloads, broker, four routes, membership and two soft-deleted users, all revoked, disabled or removed. The application role and audit rows have no delete API.

  Sessions created by the runs were revoked or have expired. Teardown destroys all of them.

### 12.6 Read-only checks performed by the Claude session (TEST-C)

```text
kubectl config current-context; kubectl config view --minify (namespace only)
kubectl get ns axiom-phase0-test --show-labels
helm list -n axiom-phase0-test; helm history axiom -n axiom
kubectl get deploy,sts,pod,svc,pvc,netpol,resourcequota,limitrange,secret -n axiom-phase0-test (Secret names only)
kubectl get pv (names, claim namespace, reclaim policy)
kubectl get pods -n axiom-phase0-test (image IDs); kubectl get pod axiom-smoke (phase, exit, finish time)
docker image inspect / docker image ls --digests (axiom-server, axiom-admin)
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/phase0-isolated (local render only, not applied)
```

### 12.7 Isolated functional evidence — harness package H-1 (TEST-X)

#### 12.7.1 Run record

| Item | Value | Class |
|---|---|---|
| Harness | `deploy/phase0-isolated/harness/phase0_harness.py`, with 67 mocked unit tests passing locally before the run. Design: `docs/operations/phase-0.2-test-harness-design.md` (revision 2a, with review hardening) | SRC |
| Review gates before execution | Contract check against server source; isolation, redaction and rollback review; integration of all major findings; Codex review | SRC |
| Executed by | Codex, once, host-side, through `kubectl port-forward` to `svc/axiom` in `axiom-phase0-test`, context `docker-desktop` | TEST-X |
| Run prefix | `p0hbf0a27cb52` | TEST-X |
| Preflight V-1 to V-10 | All passed: context, namespace (`restricted`), release `axiom` chart `axiom-0.1.3`, single Ready server pod with digest `sha256:42e702bf…`, test-only Secret, free local port, OIDC and RFC 8414 issuer plus token-exchange grant, readiness, admin login claims, no prefix collision | TEST-X |
| H1-P1 workload `client_credentials` issuance | **pass** | TEST-X |
| H1-P2 approved exchange (autonomous workload → test gateway, `gateway_authorization`) | **pass** | TEST-X |
| H1-N1 wrong audience → `invalid_target` | **pass** | TEST-X |
| H1-N2 wrong redeemer → `invalid_grant` | **pass** | TEST-X |
| H1-N3 over-broad scope → `invalid_scope` | **pass** | TEST-X |
| Cleanup | Complete. Route, broker and workloads revoked; clients and applications disabled | TEST-X |
| Redaction violation / port-forward leak | None / none | TEST-X |
| Exit code | 0 | TEST-X |
| Original release after the run | `axiom` in namespace `axiom` still revision 2 `deployed` | TEST-X |
| Raw output | Not stored in this repository. This record is a redacted summary supplied by Codex; no tokens, secrets or passwords appear in it | — |

#### 12.7.2 What H-1 proves, and its limits

Proves, for the isolated install and server image `sha256:42e702bf…` only:

- **Issuance:** a confidential workload client obtains an `at+jwt` access token with the expected issuer, audience, `identity_kind`, tenant and scope, and no session.
- **One exchange:** the autonomous workload exchange to a gateway audience. It is accepted only through an approved GATEWAY route plus an active trusted broker. The result carries the route as `authority_id`, `act` naming the workload, and lifetime capped at 5 minutes.
- **Three denials:** an unrouted audience, a token redeemed by a workload other than its owner, and a scope outside the requesting client's scope set are each refused with the expected OAuth error and no token.

Does **not** prove:

- **Original rollout:** anything about the original `axiom` release, its image (provenance still UNKNOWN), its database, identities or routes. This is not a production claim.
- **Human and BFF paths:** human login (PKCE), workforce delegation, or the BFF.
- **Hops:** any gateway-backend hop (broker → Agent or broker → resource), any Agent continuation, or any multi-hop chain.
- **Argus:** Argus Gateway, Argus enforcement, or receiver audience checks.
- **Other token behaviour:** introspection, tamper detection, revocation and its propagation, or the known gaps G-02, G-07, G-12, G-13 (deferred H-2 to H-5).
- **Network isolation:** port-forward bypasses NetworkPolicy.
- **Independent signature checks:** acceptance relied on the server's own decoder; the harness has no JWKS signature verification of its own.
- **Admin path:** it used the legacy `/auth/login` endpoint (G-20, test-only bootstrap credential).

#### 12.7.3 Remaining BFF → Gateway → Agent proof gap

This table was written after H-1 and is updated to the current status. The H-2 run is recorded in §12.8.

| Hop or property | Current status | Package |
|---|---|---|
| Human PKCE login (S256, code redemption, verifier, replay, non-member refusal) | **Evidenced, isolated install only, Axiom-issued tokens** (H-2, §12.8) | H-2 (done) |
| Workforce → BFF exchange (`authority_profile=workforce`, `exchange_subject`, `subject_sid`) | **Evidenced, isolated only** (H-2) | H-2 (done) |
| BFF → Gateway (`workload_continuation`, `gateway_authorization` from an `exchange_subject` subject) | **Evidenced, isolated only, against a test broker client, not Argus Gateway** (H-2) | H-2 (done) |
| Gateway broker → Agent (`gateway_backend`, `exchange_subject`, actor preserved, broker not the actor) | **Evidenced, isolated only, test broker** (H-2) | H-2 (done) |
| Agent → Gateway → resource (`delegated_access`) | **Evidenced, isolated only, test broker; resource is an audience only, with no receiver** (H-2) | H-2 (done) |
| Introspection of each Axiom-issued hop; tamper rejection | **Evidenced, isolated only** (H-3, §12.9). No revocation inference | H-3 (done) |
| Root-session revocation and `subject_sid` cascade through Axiom introspection and exchange | **Evidenced, isolated only** (H-4, §12.10); route/broker/workload revocation and offline receiver behavior not proven | H-4 (done) |
| Source-application → entry-workload binding (G-07) and other gap characterisation | G-02 broker-before-workload conflict, G-07 cross-app workforce exchange and G-13 user-disable failure **confirmed in the isolated install**; G-12 route revoke reaches Axiom introspection/exchange, but not a tested offline receiver. See `phase-0.2-h5-gap-characterization.md` | H-5 (in progress) |
| Real Argus Gateway, receivers, and route classes without exchange | Out of scope for Axiom-only harnesses | Phase 1.9 / Argus |
| Equivalence to the original deployed image and configuration | Not established (image provenance UNKNOWN; G-35 drift) | Later 0.2 or recovery package |

Route renewal for the original rollout is externally managed by the user and is not verified here (§7). The original routes still expire 2026-10-30/31 unless renewed.

### 12.8 Isolated functional evidence — harness package H-2 (TEST-X)

#### 12.8.1 Run record

| Item | Value | Class |
|---|---|---|
| Harness | `deploy/phase0-isolated/harness/phase0_harness_h2.py` (sha256 `30b949d2…5f7d` in the clone at the time of recording), with H-1 pinned unchanged (`10ffb18b…eebc`). 139 local mocked tests passed before the run | SRC |
| Review gates before execution | Independent source-contract trace (no blocking hop); independent safety and test review (no blockers; three majors fixed); Codex review | SRC |
| Executed by | Codex, once, host-side through `kubectl port-forward` to `svc/axiom` in `axiom-phase0-test`, context `docker-desktop` | TEST-X |
| Run prefix | `p0h4c5e00bfb3` | TEST-X |
| Preflight V-1 to V-10 | All passed | TEST-X |
| H2-P1 human PKCE login + code redemption | **pass** | TEST-X |
| H2-P2 workforce → BFF (`workforce` / `exchange_subject`) | **pass** | TEST-X |
| H2-P3 BFF → test gateway (`workload_continuation` / `gateway_authorization`, R1) | **pass** | TEST-X |
| H2-P4 test broker → Agent (`gateway_backend` / `exchange_subject`, R2; the actor stays the BFF) | **pass** | TEST-X |
| H2-P5 Agent → test gateway (R3) | **pass** | TEST-X |
| H2-P6 test broker → resource (`gateway_backend` / `delegated_access`, R4) | **pass** | TEST-X |
| H2-N1 to N9 denials: wrong verifier, separate-code replay, non-member, broker with raw human token, sibling redeemer, gateway skipped, extra scope, Agent with a broker-addressed token, unrouted audience | **all pass** | TEST-X |
| Exit code / abort / redaction violation / cleanup / port-forward leak / Location rewrites | 0 / none / none / complete / none / 0 | TEST-X |
| Original release after the run | `axiom` in namespace `axiom` still revision 2 `deployed` | TEST-X |
| Raw output | Not stored in this repository. This record is a redacted summary supplied by Codex | — |

Assertions held on every exchanged token in the passing run:

- `sub` stayed the human user;
- `subject_sid` equalled the login session, and a new `sid` was issued on every hop;
- `act` named the correct workload (`sub`, `client_id`, `workload_id`);
- `client_id` and `azp` named the redeeming client;
- `authority_id` named the expected route (P3 to P6) or the workforce entitlement (P2), equal in the response and the claim;
- `identity_kind` was `workforce` and there was no `roles` claim;
- scope was exactly `quickstart:invoke`;
- `exp − iat` was at most 300 s, and `exp` never exceeded the previous hop's.

#### 12.8.2 What is proven versus what is not

| Property | Status | Basis |
|---|---|---|
| **Axiom-issued token chain**: Axiom issues and exchanges the human → BFF → gateway → Agent → gateway → resource tokens with the asserted subject, actor, audience and authority, and refuses the nine tested misuse paths | **Proven for the isolated install and image `sha256:42e702bf…` only** | H-2 (TEST-X) |
| The broker never becomes the business actor; subject and actor stay separate across hops | **Proven, isolated only** | P4 and P6 assertions |
| **Real Argus Gateway enforcement**: the Argus Gateway validating, authorizing and dispatching with these tokens | **NOT PROVEN.** The "gateway" here was a test broker client registered in Axiom; no Argus component was involved | Out of scope for Axiom harnesses (Phase 1.9 / Argus) |
| **Receiver enforcement**: destination audience checks, rejection of gateway tokens at receivers, zero downstream calls on denial | **NOT PROVEN.** There are no receivers; `tool:meridian:<p>-tool` is an audience only | Phase 1.9 |
| **Production equivalence**: same behaviour in the original `axiom` rollout | **NOT PROVEN.** Original image provenance is UNKNOWN; configuration drift G-35 is open; the original identities and routes were not exercised | §2, §4 |
| **Root-session revocation**: existing tokens become inactive through Axiom introspection, and a descendant cannot be exchanged after revoke | **Proven for isolated Axiom only** (H-4). Not proof that offline JWKS receivers reject an already-issued token | §12.10 |
| Route, broker or workload revocation reaching already-issued tokens; user disable; receiver enforcement | TEST-X proves R4 route revoke reaches Axiom introspection/exchange, and confirms user disable leaves test sessions/tokens active. **Offline receiver enforcement and broker/workload revocation remain unproven.** | H-5 / Phase 2.9–2.10 |
| Introspection of the six Axiom-issued tokens and the three specified tamper-rejection paths | **Proven for the isolated install only**; not independent receiver or revocation proof | H-3 (§12.9) |
| Source-application → entry-workload binding (G-07) | H-5/G-07 **confirmed the gap in TEST-X**: after test user entitlement in both apps, app-B workload exchanged an app-A human token (200 with app-B authority). Original rollout and Argus are untested | H-5 / Phase 1.4 |
| Independent signature verification | Not performed; acceptance relied on Axiom's own decoder | Limitation |
| Network isolation | Not tested; port-forward bypasses NetworkPolicy | Limitation |

#### 12.8.3 Remaining journey gap after H-2

The Axiom side of the dedicated BFF → Gateway → Agent → tool token chain is now evidenced in isolation. What
remains:

- the real Argus Gateway and receivers;
- the same chain in the original rollout, or an equivalence argument for it;
- revocation classes beyond root-session revoke, and propagation to offline JWT receivers; H-3/H-4 evidence is limited to the isolated install (§§12.9–12.10);
- the G-07 binding and other gap characterisation (H-5);
- independent JWKS signature verification.

Route renewal remains externally managed by the user and is not verified (§7).

### 12.9 Isolated functional evidence — harness package H-3 (TEST-X)

Codex reviewed and ran `deploy/phase0-isolated/harness/phase0_harness_h3.py` against the existing `axiom-phase0-test` release on Docker Desktop. Its final SHA-256 was `6110ad051ea60ec4adb6a03d9360f125cce03a9ff93f8b358225ec1163641da0`; the H-1 and H-2 dependency digests remained pinned to their previously reviewed versions. All 187 local mocked H-1/H-2/H-3 tests passed before the corrected live run. This is **test-only evidence**, not an original-rollout, Argus Gateway, receiver, or revocation result.

| Run | Result | Review conclusion |
|---|---|---|
| First H-3 run | 15/16 cases passed. H3-N1 received the required 401 but failed a harness-only assertion that `WWW-Authenticate` contain `Bearer`. Cleanup was complete; no abort, redaction violation or port-forward leak. Exit 1. | The challenge scheme is not the security property of unauthenticated OAuth introspection. The assertion was over-specific; the run was **not** accepted as a pass. |
| Corrected H-3 run | 16/16 cases passed, exit 0; no abort, redaction violation or port-forward leak; cleanup complete. | H3-N1 still requires 401 and refuses `active:true`, but does not require a particular challenge scheme or body. No server or cluster configuration was changed for the correction. |

The passing cases comprise the six H-2-equivalent Axiom token-chain controls (H3-C1–C6), introspection reporting `active:true` with matching claims for all six genuine tokens (H3-I1–I6), tampered-token rejection by introspection (T1), exchange (T2), and a resource-server endpoint with an untampered control (T3), plus unauthenticated introspection denial (N1). T1 alone cannot distinguish a bad signature from an authorization-store miss or session failure. T2 and T3 have genuine-token positive controls and exercise server-side decoders, but there was **no independent JWKS verification**. None of these tests demonstrates revocation propagation (H-4).

The H-3 harness reused H-2's bounded setup, namespace/context preflights, redaction, and cleanup. The original `axiom` Helm release was checked afterward and remained revision 2 `deployed`; the isolated server remained 1/1 Ready with its separate test image. Test users, clients, workloads, routes and broker were cleaned up, but application-role and audit rows have no delete API. Test admin/browser sessions and Redis authorizations may persist until expiry as described in §12.7–§12.8; no production cleanup claim is made. Raw output and run prefixes were not retained in this repository.

### 12.10 Isolated root-session revocation evidence — harness package H-4 (TEST-X)

Codex implemented and reviewed `deploy/phase0-isolated/harness/phase0_harness_h4.py` (SHA-256 **at execution** `06fc6ccc03c1e275480756e38fa4e9b3aacfaca1bf47d9577a6edfe99241be8a`). It pins the reviewed H-3 source, which in turn pins H-2 and H-1. The full local mocked harness suite passed **192/192** before execution. Pre-run checks found context `docker-desktop`, the restricted `axiom-phase0-test` namespace, its separate test image and a 1/1 Ready server; original `axiom` was revision 2 `deployed`.

The single H-4 isolated run passed **24/24** cases, exit 0: the 16 H-3 controls; exact root-session lookup and revision-checked revoke of the newly created test user (H4-R1); all six previously active chain tokens introspecting as exactly `{"active":false}` afterward (H4-I1–I6); and a denied broker exchange using a previously issued descendant token (H4-X1, `invalid_grant`). There was no abort, redaction violation or port-forward leak, and cleanup completed. The original `axiom` release remained revision 2 `deployed` afterward; the isolated server remained 1/1 Ready. Raw JSONL and the random run prefix were not retained in the repository; this is Codex's redacted run summary.

This proves a **root IAM session** is a live boundary for Axiom introspection and token exchange in the isolated image. It does **not** prove that an offline JWKS-validating Argus Gateway or receiver checks revocation of an already-issued JWT, nor route/broker/workload revoke, user disable, production equivalence, or full Argus enforcement. Test users, clients, routes, broker and workloads were cleaned up. Application-role and audit rows have no delete API, and admin/browser sessions or Redis authorizations may remain until expiry as in §§12.7–12.9. No original rollout, Argus, production configuration, or cluster-scoped resource was changed.

After the run, Codex corrected only the harness's **dry-plan prefix label** from `p3h` to `p4h`; execution behavior was not changed or rerun. The current source SHA-256 is `0cb6709ca31a50efe7a52664c08f555083d5e7954eaf2b3a36bb32eb35232634`, and all 192 mocked tests still pass. The executed hash above, not this post-run hash, identifies the tested code.

### 12.11 H-5 gap characterization (partial functional evidence)

`phase-0.2-h5-gap-characterization.md` traces G-02, G-07, G-12, G-13 and introspection-caller scope to specific source paths. Its H-5/G-02 isolated run confirmed that broker-first then workload registration with the same OAuth client succeeds (201), with 25/25 harness cases passing and complete cleanup. Its H-5/G-07 isolated run confirmed that an app-B workload can exchange an app-A human token after app-B entitlement (200 with app-B authority), with 17/17 cases passing and complete cleanup. H-5/G-12 then confirmed a revoked disposable R4 route makes its issued resource token inactive to **Axiom introspection** and blocks another broker exchange, with 20/20 cases passing and complete cleanup. H-5/G-13 confirmed disabling a disposable user does **not** revoke its active root session, human/resource token introspection, or further broker exchange, with 21/21 characterization cases passing and complete cleanup. A separate TEST-X route-recovery drill (§12.12) showed replacement route issuance and old-token invalidity. These are gap/behavior observations, **not fixes** or proof about the original rollout or offline receiver. Broker/workload revocation and offline receiver checks remain unrun; H-5 and Phase 0.2 remain in progress pending a full recovery/acceptance review.

### 12.12 Isolated route-replacement recovery drill (TEST-X)

The reviewed `deploy/phase0-isolated/harness/phase0_harness_h5_route_recovery.py` (SHA-256 `23a6087b1043a860971b1881510d9bdc56615a9b0d9155723b812b50c545420b`) pins H-5/G-12 and passed **214/214** local mocked harness tests before one live run. In the isolated namespace, the run passed **23/23** cases with process exit 0: revoke disposable R4, create a replacement with a different authority ID (201), exchange an already-issued gateway token through the new route (200), then observe the old resource token `active:false` and new token `active:true` at Axiom introspection. The replacement route was revoked during cleanup; the harness reported no abort, incomplete cleanup, redaction violation or port-forward leak. Original `axiom` remained revision 2 `deployed`; TEST-X server remained 1/1 Ready. This validates a *mechanism* in the isolated image, not the original operator publication path, Argus receiver behavior, zero-downtime recovery, or renewal ownership.
