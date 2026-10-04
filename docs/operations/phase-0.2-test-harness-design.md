# Phase 0.2 follow-up — isolated OAuth issuance and exchange harness (design, revision 2)

Status: H-1, H-2 and H-3 were implemented and executed against the isolated test install; their actual results and limits are in the working baseline §§12.7–12.9. Sections 1–10 below preserve the original pre-execution design and are not the current run-status checklist. Recorded 2026-10-01 in clone
`axiom-changes`, branch `hardening/phase-0-baseline`, HEAD `74e7e56`, with Codex's uncommitted changes
preserved.

Revision 2 applies the Codex review:

- The harness runs **host-side** through `kubectl port-forward`. There is no in-cluster Pod, ConfigMap,
  NetworkPolicy or image pull.
- The per-run prefix is unpredictable.
- The pre-write verification list now matches the review.
- The first package is reduced to issuance, one authorized exchange and three denials.
- PKCE, revocation, introspection, tampering and gap characterisation are deferred.
- The tamper method is corrected (§8).

This is not Phase 0.3. It is a black-box functional test of the **isolated** release in `axiom-phase0-test`
(baseline document §12) and makes **no production claim**.

## 1. Scope

In scope (package H-1):

- workload token issuance (`client_credentials`);
- one authorized RFC 8693 exchange (autonomous workload → test gateway, `gateway_authorization`);
- wrong-audience, wrong-redeemer and over-broad-scope denials.

Out of scope for H-1 (deferred, §8):

- PKCE and the human/BFF chain;
- revocation;
- introspection;
- token tampering;
- G-02, G-07, G-12, G-13 characterisation;
- receivers.

Never in scope:

- the original `axiom` namespace, release, database, identities or images;
- Argus, quickstart identities or production secrets;
- unchanged `scripts/verify-*.py`;
- cluster-scoped resources;
- any change to the isolated release's Helm values or Kubernetes objects.

## 2. Test target

| Item | Value |
|---|---|
| Kube context | `docker-desktop`. Passed explicitly as `--context docker-desktop` on every call. |
| Namespace | `axiom-phase0-test` (Pod Security `restricted`). Passed explicitly as `-n axiom-phase0-test` on every call. |
| Release | `axiom`, chart `axiom-0.1.3`, status `deployed` |
| Expected server image digest | `sha256:42e702bffa8ebf863f976587297a32914eb76bd1382df78fcd90c5630740903f` (`axiom-server:phase0-codex-74e7e56`) |
| Service | `svc/axiom` port 8084 (ClusterIP) |
| Expected issuer | `http://axiom.axiom-phase0-test.svc.cluster.local:8084` |
| Transport | `http://127.0.0.1:<port>`, where `<port>` is a unique local port |
| Tenant | `meridian` (isolated bootstrap tenant) |
| Business scope | `quickstart:invoke`, already approved in the isolated release values |
| Admin credential | Test-namespace Secret `axiom-runtime`, key `axiom.bootstrap.admin-password`, used with `POST /auth/login` (legacy path G-20, test-only) |
| Interpreter | `/opt/homebrew/bin/python3.13` (3.13.3), run as `-I -B` (isolated mode, no bytecode). Standard library only. |

The authorization server signs tokens with its **configured** issuer, not the request host. Tokens obtained
through `127.0.0.1` therefore still carry the expected issuer above. The harness never follows absolute URLs
from discovery metadata; it calls fixed paths on the forwarded base URL.

## 3. Implementation outline (to be written after review; not yet created)

- File: `deploy/phase0-isolated/harness/phase0_harness.py`, standard library only (`subprocess`, `urllib`,
  `json`, `base64`, `hashlib`, `secrets`, `socket`, `time`).
- Every `kubectl` and `helm` invocation is built from a fixed template that always includes
  `--context docker-desktop` (or `--kube-context docker-desktop` for helm) and `-n axiom-phase0-test`. The
  harness refuses to build a command for any other namespace. It never addresses namespace `axiom`, and never
  reads Argus or other namespaces.
- Port-forward lifecycle:
  1. Choose a random port in 41000–48999 with `secrets`, and confirm it is free by binding `127.0.0.1` briefly.
  2. Start `kubectl --context docker-desktop port-forward -n axiom-phase0-test svc/axiom <port>:8084 --address 127.0.0.1` as a child process.
  3. Wait up to 20 s for the "Forwarding from 127.0.0.1:<port>" line.
  4. On exit, success or failure, terminate the child in `try/finally` and confirm it has stopped.
- No file is written except stdout. The test admin password and generated client secrets are held in memory only.

### Redaction rules

- Never print tokens, secrets, passwords or `Authorization` headers. To correlate tokens, print `sha256(token)[:12]`.
- Claims are read by base64url-decoding the JWT header and payload, for display only. Printed claims are limited
  to `typ`, `kid`, `iss`, `sub`, `aud`, `scope`, `exp`, `iat`, `tenant_id`, `identity_kind`, `client_id`, `azp`,
  `act`, `token_use`, `authority_profile`, `authority_id`, `sid`, `subject_sid`.
- Server error bodies are printed as `error` and `error_description` only.

## 4. Verification before any admin write (abort on any failure)

The first six checks use `kubectl` or `helm` only; the port-forward starts after V-6.

| # | Check | Expected |
|---|---|---|
| V-1 | `kubectl config get-contexts docker-desktop` | Context exists. The harness uses it explicitly rather than relying on the current context. |
| V-2 | `kubectl get ns axiom-phase0-test -o json` | Exists; label `pod-security.kubernetes.io/enforce=restricted`. Record its `creationTimestamp`. |
| V-3 | `helm --kube-context docker-desktop list -n axiom-phase0-test -o json` | Exactly one release: `axiom`, chart `axiom-0.1.3`, status `deployed` |
| V-4 | `kubectl get pods -n axiom-phase0-test -l app.kubernetes.io/instance=axiom,app.kubernetes.io/component=server -o json` | Exactly one Ready server pod, whose `imageID` ends with the expected digest in §2 |
| V-5 | `kubectl get secret axiom-runtime -n axiom-phase0-test -o json` (metadata and key **names** only, then a separate read of the one key) | Secret is in `axiom-phase0-test`; `creationTimestamp` ≥ the namespace's (created for this namespace); key `axiom.bootstrap.admin-password` present. The value is base64-decoded in memory, never printed or written. |
| V-6 | Port check | Chosen port is free on `127.0.0.1` |
| V-7 | `GET /.well-known/openid-configuration` and `GET /.well-known/oauth-authorization-server` via the forward | Both return `issuer` equal to the expected issuer exactly. The RFC 8414 metadata's `grant_types_supported` contains `urn:ietf:params:oauth:grant-type:token-exchange`; the server's metadata customizer is attached there (`SecurityConfig.java:232-234`), and its presence in the OIDC document is framework-default behaviour that is not relied on. |
| V-8 | `GET /actuator/health/readiness` via the forward | `{"status":"UP"}` |
| V-9 | `POST /auth/login` as `admin` | 200. Decoded token: `iss` = expected issuer, `tenant_id=meridian`, `aud=["axiom-api"]`, `roles` contains `platform_admin` |
| V-10 | `GET /admin/tenants/meridian/applications` | No existing `applicationKey` starts with this run's prefix |

Not claimed: `kubectl port-forward` reaches the pod through the kubelet and **bypasses NetworkPolicy**. This
harness says nothing about namespace network isolation. That isolation is a separate property recorded in
baseline §12.2 (default-deny, ClusterIP-only Services).

## 5. Per-run test identities

The prefix is `p0h` + `secrets.token_hex(5)` (10 lowercase hex characters), for example `p0h9c41e07ab2`. It is
generated at run start, printed once, and not derivable from time. All keys satisfy the API patterns
(`[a-z][a-z0-9-]{1,62}` for applications, `[a-z][a-z0-9-]{1,98}` for clients).

| Object | Value (`<p>` = prefix) | API |
|---|---|---|
| Application `entry` | key `<p>-entry`, audience `agent:meridian:<p>-entry` | `POST /admin/tenants/meridian/applications` |
| Confidential client `entry` | `<p>-entry`, scopes `[quickstart:invoke]` (token exchange is enabled automatically for confidential clients) | `POST …/applications/{appId}/clients` |
| Application `gateway` | key `<p>-gateway`, audience `<p>-gateway` (test broker, not Argus) | same |
| Confidential client `gateway-broker` | `<p>-gateway-broker`, scopes `[quickstart:invoke]` | same |
| Application `sibling` | key `<p>-sibling`, audience `agent:meridian:<p>-sibling` | same |
| Confidential client `sibling` | `<p>-sibling`, scopes `[quickstart:invoke]` | same |
| Workloads | `agent:<p>-entry:test` → client `<p>-entry`; `agent:<p>-sibling:test` → client `<p>-sibling` | `POST /admin/tenants/meridian/ciam/agent-workloads` |
| Broker | client `<p>-gateway-broker`, `gatewayAudience=<p>-gateway`, scopes `[quickstart:invoke]` | `POST /admin/tenants/meridian/agent-exchange/brokers` |
| Route R1 | source `entry` workload → `GATEWAY`, audience `<p>-gateway`, scopes `[quickstart:invoke]`, purpose `phase0 H-1 isolated test`, `expiresAt` = now + 1 h | `POST /admin/tenants/meridian/agent-exchange/routes` |

There are no users, public clients, memberships or roles in H-1.

Contract details confirmed against source (contract check, revision 2a):

- **Request fields:** create-application requires `displayName`; create-workload requires `name`; clients are created with `clientType: "CONFIDENTIAL_SERVICE"`.
- **Client identifiers:** the client UUID used for cleanup is `client.id`, and the one-time secret is `serviceSecret`.
- **Order:** the broker must exist before R1. Route creation without an active broker for the audience returns **401** from the admin API, which the harness treats as a setup failure.

## 6. H-1 cases

Exchange requests:

- use HTTP Basic for the redeeming client;
- form fields `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
  `subject_token=<entry workload token>`,
  `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, and `requested_token_type` with the
  same urn.

The cases exercise this source path:

- `AgentExchangeAuthorityService.resolve` → `resolveAutonomousWorkload`
  (`server/src/main/java/com/openwolf/iam/service/AgentExchangeAuthorityService.java:206-222,365-377`);
- the provider scope check (`server/src/main/java/com/openwolf/iam/auth/TokenExchangeAuthenticationProvider.java:88-89`).

| ID | Class | Action | Expected |
|---|---|---|---|
| H1-P1 | positive | `<p>-entry` `client_credentials`, `scope=quickstart:invoke` | 200, `token_type=Bearer`. Header `typ=at+jwt`. `iss` = expected issuer; `sub=client_id=<p>-entry`; `aud=["agent:meridian:<p>-entry"]`; `identity_kind=workload`; `tenant_id=meridian`; `scope` = `quickstart:invoke`; no `sid`; `exp − iat` ≤ 3600 |
| H1-P2 | positive | `<p>-entry` exchanges H1-P1, `audience=<p>-gateway`, `scope=quickstart:invoke` | 200. `issued_token_type` = access_token urn; response `authority_id` = R1 id. Claims: `sub=<p>-entry`; `aud=["<p>-gateway"]`; `act.sub=agent:<p>-entry:test`; `act.client_id=<p>-entry`; `authority_profile=workload_continuation`; `token_use=gateway_authorization`; `authority_id` = R1 id; `scope` = `quickstart:invoke`; `exp` ≤ min(H1-P1 `exp`, now + 300 s + 5 s skew) |
| H1-N1 | wrong audience | `<p>-entry` exchanges H1-P1, `audience=agent:meridian:<p>-sibling` (no GATEWAY route) | 400 `invalid_target`; no `access_token` in the body |
| H1-N2 | wrong redeemer | `<p>-sibling` exchanges H1-P1 (subject `client_id` is not the requester), `audience=<p>-gateway` | 400 `invalid_grant`; no `access_token` |
| H1-N3 | over-broad scope | `<p>-entry` exchanges H1-P1, `audience=<p>-gateway`, `scope=quickstart:invoke cards:incident.read`. `cards:incident.read` **is** deployment-approved, so the denial comes from the requester client's scope set (`TokenExchangeAuthenticationProvider.java:88-89`), not from scope approval. | 400 `invalid_scope`; no `access_token` |

Claim-format notes from the contract check:

- **`scope` format:** the claim is a JSON array (`["quickstart:invoke"]`). The harness accepts an array or a space-separated string and compares the values as a set.
- **H1-P2 session:** the exchanged token carries a `sid`, because a durable session is written. The harness records this and does not assert on it.
- **H1-P2 extra assertions:** `client_id = azp = <p>-entry`, `identity_kind = workload`, and `act.workload_id` equal to the entry workload's id.

Pass criterion: all five match. The successful exchange in H1-P2 also shows the server accepted H1-P1's
signature, issuer and type through its own subject-token decoder. Mismatches are reported as observed. There
are no retries.

## 7. Abort, cleanup and rollback

Abort:

- any V-1 to V-10 failure;
- any 5xx;
- any admin write failure during setup;
- loss of the port-forward.

On abort, the harness skips the remaining cases, runs cleanup for whatever was created, stops the
port-forward and exits non-zero.

Cleanup (default, after the cases; each step reported; a cleanup failure does not change case results):

1. Revoke R1 (`POST …/agent-exchange/routes/{id}/revoke`).
2. Revoke the broker (`POST …/agent-exchange/brokers/{id}/revoke`).
3. Revoke both workloads (`POST …/ciam/agent-workloads/{id}/revoke`).
4. Disable the three clients (`DELETE …/applications/{appId}/clients/{clientUuid}`).
5. Disable the three applications (`DELETE …/applications/{appId}`).
6. Stop the port-forward and confirm the child process has exited.

Hardening from the isolation, redaction and rollback review (implemented and unit-tested):

- **Process isolation:**
  - The port-forward runs in its own session, so a terminal Ctrl-C does not kill it before cleanup.
  - SIGTERM and SIGHUP are converted into a clean abort.
  - Child processes inherit no proxy variables.
  - `-s`, `--server`, `--cluster`, `--user`, `--token`, `--as*` and `--insecure-skip-tls-verify` are rejected by the command builder.
- **Cleanup robustness:**
  - If the port-forward was lost, cleanup first starts one replacement forward on a fresh local port.
  - An unexpected exception in one cleanup step does not stop the remaining steps.
  - One admin re-login is attempted on the first 401 during cleanup.
  - Server-issued ids must match `^[A-Za-z0-9-]{1,64}$` before they are placed in a cleanup path.
- **Redaction:** the redactor also covers URL-encoded forms and the bare base64 Basic credential.
- **Exit codes:**
  - `0` means all five cases passed and nothing else needs attention.
  - `1` means a case failed.
  - `2` means any of: abort, a redaction violation, incomplete cleanup, or a port-forward that did not exit. Case results themselves are never changed by cleanup.

Rollback position:

- The harness creates **no Kubernetes objects**. Stopping the port-forward removes its only runtime artefact.
- Records written to the isolated database through the API persist in revoked or disabled form: applications,
  clients, workloads, broker, route, the admin login session and audit rows. There is no delete API for most of
  them.
- A clean database requires the namespace teardown in baseline §12.4, followed by a Codex-authorized
  recreation (data-loss caveats in baseline §12.5).
- There is nothing to roll back elsewhere: the harness never addresses namespace `axiom` or Argus.

## 8. Deferred packages (not part of H-1)

| Package | Content |
|---|---|
| H-2 | PKCE human login, the BFF → gateway → Agent → resource chain, and PKCE negatives (missing S256, wrong verifier, code replay, non-member) |
| H-3 | Introspection (active tokens, unauthenticated caller) and the corrected tamper case below |
| H-4 | Revocation: session revoke, `subject_sid` cascade, no exchange after revocation |
| H-5 | Characterisation of G-02, G-07, G-12, G-13 and introspection-caller scope |

Corrected tamper method for H-3:

1. Split the JWT.
2. Base64url-decode the signature into bytes (256 bytes for RS256 with a 2048-bit key).
3. XOR byte index `len(sig) // 2` with `0x01`.
4. Re-encode without padding.
5. Assert that the re-encoded string differs and decodes to different bytes, then submit.

Changing only the last base64url character is unreliable. For a 256-byte signature, the final character
carries 4 unused low-order bits (256 bytes = 85 full 3-byte groups + 1 byte, encoded as 2 characters = 12 bits), so some substitutions decode to identical bytes, and others are rejected as
non-canonical encoding rather than as a bad signature.

## 9. Limitations

- **No isolation claim:** port-forward bypasses NetworkPolicy, so no network-isolation property is tested.
- **Single pod:** a Service port-forward binds to one pod. With one replica this is the only pod.
- **Server-side signature checking only:** acceptance relies on the server's own decoder. There is no
  independent JWKS signature verification, because the harness is standard library only.
- **Legacy admin login:** the admin path depends on `/auth/login` (G-20).
- **Scope of results:** they apply only to the isolated install and image `sha256:42e702bf…`. They say nothing
  about the original release, its image provenance, configuration drift (G-35), the full BFF → Gateway →
  Agent journey, or route renewal. The first four remain open; route renewal is externally managed by the user and is not verified here.
- **Local credential exposure:** the host process holds a test-only admin password in memory for the run's
  duration.

## 10. Review checklist for Codex

- [ ] Host-side, port-forward transport accepted; no in-cluster objects or image pulls (§2–§3).
- [ ] Pre-write verification V-1 to V-10 complete; the port-forward isolation non-claim is stated (§4).
- [ ] Unpredictable prefix and minimal identity set (§5).
- [ ] H-1 cases and expectations agreed (§6).
- [ ] Abort, cleanup and rollback acceptable (§7).
- [ ] Deferred packages and corrected tamper method recorded (§8).
- [ ] After review: harness file written, then a single execution run in `axiom-phase0-test`. Execution waits for Codex review.

## 11. Package H-2 — human PKCE and the BFF → Gateway → Agent → resource chain (isolated run passed)

Status: implemented in `deploy/phase0-isolated/harness/phase0_harness_h2.py`, with mocked unit tests in
`test_phase0_harness_h2.py`. Codex's isolated run passed 15/15 cases; see working baseline §12.8. H-1 files are unchanged; a unit test pins their
SHA-256. H-2 reuses H-1's preflight V-1 to V-10, transport, redaction, cleanup robustness and exit codes.

### 11.1 Source contract

An independent source trace found **no blocking hop**. All six positive hops resolve for the identities below.
The RESOURCE destination needs only an active application audience, not a client
(`AgentExchangeAuthorityService.java:173-178,446`; `TenantApplicationService.java:211-216`).

### 11.2 Identities (per-run prefix `<p>`)

- **Applications:**

  | Application | Audience |
  |---|---|
  | `<p>-bff` | `agent:meridian:<p>-bff` |
  | `<p>-gateway` | `<p>-gateway` |
  | `<p>-agent` | `agent:meridian:<p>-agent` |
  | `<p>-tool` | `tool:meridian:<p>-tool` (no client) |
  | `<p>-sibling` | `agent:meridian:<p>-sibling` |

- **Clients:**
  - Public client `<p>-human-web`, redirect `http://127.0.0.1:9/callback`. The harness never requests the redirect; it only reads `code` and `state` from it.
  - Confidential clients `<p>-bff`, `<p>-gateway-broker`, `<p>-agent` and `<p>-sibling`.
- **Workloads, broker and routes:**
  - Workloads for the bff, agent and sibling clients.
  - Broker `<p>-gateway-broker`, registered before the routes.
  - Routes, each with scope `quickstart:invoke` and a 1-hour TTL:

    | Route | From | To | Audience |
    |---|---|---|---|
    | R1 | bff | GATEWAY | `<p>-gateway` |
    | R2 | bff | AGENT (agent) | `agent:meridian:<p>-agent` |
    | R3 | agent | GATEWAY | `<p>-gateway` |
    | R4 | agent | RESOURCE | `tool:meridian:<p>-tool` |

- **People:**
  - Role `<p>-operator` (`quickstart:invoke: allow`) in `<p>-bff`.
  - Users `<p>-user` (member with the role) and `<p>-nomember`, with unique ids and in-memory passwords.
  - All membership and role setup completes before any login, because the workforce `authority_id` embeds the entitlement revision.

### 11.3 Cases

| ID | Action | Expected |
|---|---|---|
| H2-P1 | PKCE login (`Accept: text/html`, `/login` with `_csrf`, S256) and code redemption by `<p>-user` | `aud=[agent:meridian:<p>-bff]`, `client_id=<p>-human-web`, `identity_kind=workforce`, `sid` present, `roles ∋ <p>-operator` |
| H2-P2 | `<p>-bff` exchanges P1 (workforce → BFF) | `workforce` / `exchange_subject`; `act.sub=agent:<p>-bff:test`; `client_id=azp=<p>-bff`; `authority_id` starts with `workforce:`; `subject_sid` = P1 `sid` |
| H2-P3 | `<p>-bff` exchanges P2 → `<p>-gateway` | `workload_continuation` / `gateway_authorization`; `act` = bff; `authority_id` = R1 |
| H2-P4 | broker exchanges P3 → `agent:meridian:<p>-agent` | `gateway_backend` / `exchange_subject`; `act` **still** bff (the broker is never the actor); `client_id=azp=broker`; `authority_id` = R2 |
| H2-P5 | `<p>-agent` exchanges P4 → `<p>-gateway` | `workload_continuation` / `gateway_authorization`; `act` = agent; `authority_id` = R3 |
| H2-P6 | broker exchanges P5 → `tool:meridian:<p>-tool` | `gateway_backend` / `delegated_access`; `act` = agent; `authority_id` = R4 |
| H2-N1 | Wrong `code_verifier` on its own fresh code | 400 `invalid_grant` |
| H2-N2 | Replay of a **separate** fresh code (the P1 code is never replayed) | 400 `invalid_grant` |
| H2-N3 | Non-member logs in, then authorizes | 403 and no code issued |
| H2-N4 | Broker exchanges raw P1 | 400 `invalid_grant` |
| H2-N5 | `<p>-sibling` exchanges P2 | 400 `invalid_grant` |
| H2-N6 | `<p>-bff` exchanges P2 directly to the agent audience | 400 `invalid_target` |
| H2-N7 | P3 hop with extra scope `cards:incident.read` | 400 `invalid_scope` |
| H2-N8 | `<p>-agent` exchanges P3 (addressed to the broker) | 400 `invalid_grant` |
| H2-N9 | Broker exchanges P5 to the bff audience (no route) | 400 `invalid_target` |

Every exchanged token also asserts:

- `sub` is the user, `tenant_id=meridian`, `identity_kind=workforce`, `scope={quickstart:invoke}`;
- `subject_sid` equals the P1 `sid`;
- `exp ≤ min(previous exp, request time + 305 s)`.

Dependent cases are skipped if their prerequisite fails. There are no retries.

### 11.4 Isolation, redaction and cleanup additions

- **Location handling:**
  - Followed only if relative or exactly `http://127.0.0.1:<port>`.
  - The redirect URI is parsed, never requested.
  - Another host is rewritten onto the forward only for `/oauth/authorize` or `/login`; a rewrite event is recorded and the foreign host is never contacted.
  - At most 5 redirects per login.
- **Cookies:** a per-user in-memory cookie jar, sent only to the forward.
- **Never printed:** codes, verifiers, cookies, CSRF tokens, user passwords and full Location URLs. Only the path and a `code_present` flag are output.
- **Cleanup order:**
  1. Revoke the test users' ACTIVE sessions.
  2. Revoke R4, R3, R2, R1, the broker and the workloads.
  3. Disable the clients, remove the membership, soft-delete the users, disable the applications.
- **Residue:** the application role and audit rows have no delete API and persist in the isolated database.

### 11.5 Run gate

Execution needs Codex review and authorization. The single command, from the clone:

```bash
cd /Users/srirajkadimisetty/projects/axiom-changes/deploy/phase0-isolated/harness && /opt/homebrew/bin/python3.13 -I -B phase0_harness_h2.py --package h2 --execute
```

The expected summary is `package: "H-2"`, `passed: 15`, `aborted: false`, `redaction_violation: false`,
`cleanup_complete: true`, `port_forward_leaked: false`, with exit 0.

Limitations:

- results apply only to the isolated image;
- no Argus Gateway, receivers, introspection, tamper detection, revocation propagation or gap characterisation (H-3 to H-5);
- admin access uses `/auth/login` (G-20);
- port-forward makes no network-isolation claim.

### 11.6 Independent review outcome (applied before handover)

No blockers. The fixes applied:

- **Location rewrite:** only the configured issuer's own scheme, host and port may be mapped onto the forward,
  and only for `/oauth/authorize` and `/login`. Any other host is rejected. Rewrites are counted in the summary
  as `location_rewrites`.
- **Contract assertions added:**
  - **P1:** exact roles; absence of `azp`, `act`, `token_use` and `subject_sid`.
  - **P2:** exact workforce `authority_id` `workforce:<bffAppId>:<user>:<rev>`, with `<rev>` taken from the
    role-assignment response. Source says 2: create = 1, role assignment +1
    (`TenantApplicationMembership.java:46,56-58`; `ApplicationAccessService.java:158`).
  - **All hops:** full `act` (`sub`, `client_id`, `workload_id`); P5 `client_id = azp = <p>-agent`;
    `identity_kind = workforce`; no `roles`; `0 < exp − iat ≤ 300`; a new `sid` on every hop; response
    `authority_id` equal to the claim.
- **Expiry cap confirmed:** every exchange is capped at the subject token's expiry
  (`TokenExchangeAuthenticationProvider.java:104-110`), so `exp ≤ previous exp` is correct for every hop.
- **User safety:** `GET /users/{id}` must return 404 before `POST /users`, because the server merges onto an
  existing id; this is a separate security finding, flagged as its own task. The returned id must equal the
  requested id. If it differs, the account created under the returned id is recorded for cleanup.
- **Integrity and redaction:** H-2 refuses to load an H-1 file whose SHA-256 differs from the reviewed digest.
  `state` and `nonce` are registered with the redactor.

## 12. Package H-3 — introspection of each hop and tampered-signature denial (isolated run passed)

Status: implemented in `deploy/phase0-isolated/harness/phase0_harness_h3.py`, with mocked unit tests in
`test_phase0_harness_h3.py`. Codex's corrected isolated run passed 16/16 cases; the first run passed 15/16 and failed an over-specific harness challenge assertion. Details and limits are recorded in the working baseline §12.9. H-3 pins H-1 (`10ffb18b…eebc`) and H-2
(`30b949d2…f7d`) by SHA-256 before loading them. Both are unchanged. H-3 reuses H-2's preflight V-1 to V-10,
setup, login, transport guards, redaction, cleanup and exit codes, with its own per-run prefix `p3h<10 hex>`.

### 12.1 Source contract (independent trace)

- **Who may call:** `/oauth/introspect` accepts any authenticated confidential client, with no caller or
  audience restriction.
- **Active response:** 200 with every JWT claim plus `active: true`. `scope` is space-delimited.
- **Inactive response:** 200 with exactly `{"active":false}`.
- **What runs:** tokens carrying `act` (C2 to C6) go through the full validator chain: signature, session and
  `subject_sid`, plus route, broker or workload authority. So introspection must run before cleanup.
- **Side effect:** introspection updates `last_seen` on those sessions and on the root session. It writes no
  audit rows.

### 12.2 Cases

| ID | Action | Expected |
|---|---|---|
| H3-C1 to C6 | Fresh H-2 chain (P1 to P6 checks reused) | As H-2 |
| H3-I1 to I6 | Introspect each chain token immediately, as `<p>-sibling` | 200, `active: true`; echoed `sub`, `aud`, `client_id`, `scope`, `exp`/`iat` and, for exchanged tokens, `act`, `token_use`, `authority_profile`, `authority_id`, `sid`, `subject_sid` match the issued token |
| H3-T1 | Introspect C6 with one signature byte flipped (decoded bytes, middle index) | 200, exactly `{"active":false}`. Rejection is shown; the cause is **not** distinguishable (store miss, signature or session) |
| H3-T2 | Tampered C5 as `subject_token` in the exact C6 request (C6 is the untampered control) | 400 `invalid_grant`. Exercises the RS256 subject-token decoder |
| H3-T3 | Untampered admin token on `GET /api/me/sessions` (control, 200), then the same token with its signature tampered | 401 with `WWW-Authenticate` containing `invalid_token`. Exercises the resource-server RS256 decoder |
| H3-N1 | Introspection without client authentication (`Accept: application/json`) | 401; never `active: true`. No particular `WWW-Authenticate` scheme or body is required |

### 12.3 What H-3 proves and does not prove

- **Proves, isolated install only:**
  - **I1 to I6:** genuine chain tokens introspect as active, with claims consistent with issuance.
  - **T2 and T3:** a modified RS256 signature is rejected on the token-exchange and resource-server paths, each
    with an untampered positive control.
  - **T1:** a tampered token is not reported as active.
- **Does not prove:**
  - **Revocation of any kind.** The untampered tokens remain valid, and no session, route, broker, workload or
    user revocation is exercised; that is H-4. Signature validation is **not** revocation evidence.
  - **That T1's rejection was caused by signature verification specifically.**
  - **Key rotation, `alg`/`kid` confusion, or forged but validly signed claims.**
  - **Argus Gateway or receiver enforcement, or production equivalence.**

### 12.4 Run gate

Execution needs Codex review and authorization. The single command, from the clone:

```bash
cd /Users/srirajkadimisetty/projects/axiom-changes/deploy/phase0-isolated/harness && /opt/homebrew/bin/python3.13 -I -B phase0_harness_h3.py --package h3 --execute
```

The expected `h3_summary` is `package: "H-3"`, every case passed, `aborted: false`, `redaction_violation: false`,
`cleanup_complete: true`, `port_forward_leaked: false` and `location_rewrites: 0`, with exit 0.

### 12.5 Independent review outcome (applied before handover)

No blockers. The fixes applied:

- **Introspection field coverage tightened.**
  - `iss`, `tenant_id` and `identity_kind` are now required on every introspected token.
  - `azp`, `act.workload_id` and `token_type = "Bearer"` (a literal match) are now required on exchanged tokens.
- **Session ids in cleanup output hashed.** The IAM session ids printed in inherited H-2 cleanup step names equal
  the JWT `sid`, so H-3 prints them as `sha256_12:` only.
- **Evidence wording corrected.**
  - T1 now carries its own claim: "tampered token not reported active; cause not distinguishable; not
    signature-specific evidence; not revocation evidence".
  - T2 now reads "expected to exercise the subject-token RS256 decoder; `invalid_grant` by itself does not
    distinguish the cause".
  - Every tamper claim must state "not revocation evidence"; the expectation table enforces this when it is loaded.

Minor items recorded, not changed:

- the H-1/H-2 pins hash the file, and `exec_module` then reads it again;
- failed chain cases may print `error_description` (inherited from the accepted H-2 behaviour);
- the full fake-server run uses short fake signatures; the 256-byte RS256 case is covered by the tamper-helper
  unit tests.
