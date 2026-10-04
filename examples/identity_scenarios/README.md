# Axiom identity cookbook

A developer guide, with runnable Python examples, for integrating an application, API, gateway, broker or workload
with **Axiom**, the consumer-neutral identity provider. Every example talks HTTP to a real Axiom server backed by
PostgreSQL and Redis. Each one shows the success path and the refusals that matter, and the same code runs as the
contract test suite.

> Status: draft evidence for review. Nothing here claims production readiness, consumer enforcement or Codex acceptance.
> The acceptance target is the IDP capability checklist (IDP-01–15). Results and open gaps:
> `docs/operations/axiom-integration-capability-ledger.md`. Integration contract:
> `docs/architecture/axiom-identity-provider-contract.md`; machine-readable profile: `provider-profile.example.json`.
> (The earlier B/O/C catalogue and its ledger, `docs/operations/axiom-integration-scenario-ledger.md`, remain as
> continuity references.)

## IDP capability examples (start here)

| Capability | Example (`idp/`) | Population |
|---|---|---|
| IDP-01 discovery, metadata, keys | `idp01_metadata.py` | — |
| IDP-02 browser sign-in (code + S256 PKCE) | `idp02_browser_signin.py`, browser: `tests/test_idp_browser.py` | workforce, CIAM |
| IDP-03 client credentials (secret, `private_key_jwt`) | `idp03_client_credentials.py` | software |
| IDP-04 token contract (audience, scope, type, lifetime) | `idp04_token_contract.py` | workforce |
| IDP-05 token exchange and continuation | `idp05_token_exchange.py` | workforce, CIAM, software |
| IDP-06 refresh tokens | `idp06_refresh.py` | workforce, CIAM |
| IDP-07 introspection | `idp07_introspection.py` | all |
| IDP-08 revocation and logout | `idp08_revocation_logout.py`, browser: `tests/test_idp_browser.py` | workforce |
| IDP-09 credential lifecycle and audit | `idp09_key_client_lifecycle.py`, `oauth/o08…`, `tests/test_disruptive.py` | software |
| IDP-10 isolation | `idp10_isolation.py` | all, two tenants |
| IDP-11 directory administration (SCIM, roles, customers) | `idp11_directory_admin.py` | workforce, CIAM |
| IDP-12 client administration and consent | `idp12_client_admin.py`, browser: `tests/test_idp_browser.py` | workforce, CIAM |
| IDP-13/14/15 conditional profiles (not selected / partial) | `idp13_15_conditional_profiles.py` | — |

Runtime calls in these examples are standard OAuth/OIDC requests; provisioning goes through Axiom's management APIs
(`axiom_cookbook/context.py`, `ciam.py`: the provider-specific *setup adapter*). Assertions use portable claims
(`iss`, `sub`, `aud`, `exp`, `client_id`, `scope`, `act`) and never require Axiom-specific claims.

## What you will learn

| If you are building… | Start with |
|---|---|
| anything | `basics/b01_connect.py`, `oauth/o01_discovery_and_validation.py` |
| a web app for employees (workforce) | `oauth/o02_workforce_authorization_code.py`, `basics/b04_roles_and_entitlements.py` |
| a service or scheduled job | `oauth/o04_client_credentials.py`, `basics/b09_workloads_and_edges.py` |
| a service acting for a signed-in person | `oauth/o05_token_exchange.py`, `consumer_contracts/c03_workload_chains.py` |
| an API, tool server or gateway that receives tokens | `consumer_contracts/c01_receiver_enforcement.py`, `oauth/o06_introspection_revocation_logout.py` |
| a customer-facing app (CIAM) | `ciam/b06…`, `ciam/b07…`, `ciam/b08_consent_grants.py`, `ciam/o03_customer_login.py` |
| long-running or unattended work | `oauth/o07_renewal.py` |
| credential and key operations | `oauth/o08_key_and_credential_lifecycle.py`, `basics/b10_sessions_and_lifecycle.py` |

Three identities stay separate throughout:

- **the authenticated OAuth client** (`client_id`);
- **the represented person or customer** (`sub`, with `identity_kind`);
- **the acting workload** (`act`).

Registering something never grants authority by itself. Authority comes only from an explicit membership, edge,
consent grant or standing grant, and Axiom re-checks it live.

## Layout

```text
examples/identity_scenarios/
  README.md                this guide
  pyproject.toml           package + pinned minimums (requests, PyJWT[crypto], cryptography; pytest for tests)
  provider-profile.example.json  the IDP worksheet for Axiom: endpoints, grants, client authentication, lifetimes
  axiom_cookbook/          shared support library (import this in your own code)
    target.py              refuses non-loopback/shared/production targets unless explicitly allowed
    http.py                one origin only: credentials can never leave the verified Axiom origin; no auto-redirects
    redaction.py           Secret wrapper + scrubbing; tokens, codes, passwords never print
    oauth.py               authorization code + PKCE (real login form), client credentials, exchange, introspect, revoke
    tokens.py              JWKS validation of access and ID tokens (issuer/JWKS pinned to the target)
    ciam.py                customer provisioning, verification, sign-in, consent grants
    receiver.py            a generic receiver fixture (offline vs online validation)
    topology.py            a small generic exchange topology (apps, workloads, intermediary, resource, edges)
    context.py             run context: operators, fixture namespace, owned-record registry and cleanup
    estate.py              disposable estate: PostgreSQL, Redis, Cerbos containers + bootstrap + Axiom jar
    example.py             Outcome (allowed/denied/facts/consumer obligations) and the standalone runner
  basics/                  B01–B05, B09–B11: connection, people, apps/clients, roles, teams, workloads, sessions
  ciam/                    B06–B08, O03: customers, customer app access, consent, customer sign-in
  oauth/                   O01–O09: discovery, flows, exchange, status, renewal, credentials, capabilities
  consumer_contracts/      C01–C05: what receivers and brokers must do (receiver, isolation, chains, trust, assurance)
  idp/                     IDP-01–12 baseline contracts and the IDP-13–15 conditional-profile report
  tests/                   pytest suites that run the same example code, plus offline safety tests
  evidence/                last-run.json per pytest run: real pass/fail/skip counts, dependency versions, jar
                           hash and a content fingerprint of the exercised source (sanitized; git-ignored)
```

Every example module opens with the same nine answers:

1. what it teaches and for which population;
2. the operator and permissions setup needs;
3. which records it creates;
4. the exact calls;
5. how tokens change hop by hop;
6. its positive and denial assertions;
7. what expires or is revoked, and the effect;
8. how cleanup works;
9. what the consumer must enforce itself.

Each module exposes `run(ctx) -> Outcome`.

## Prerequisites

- Python ≥ 3.11 (evidence runs used 3.12.7) and `pip install -e '.[test]'` (or `requests PyJWT[crypto] cryptography pytest`).
- Docker (local), Java 25, and a built server jar:
  ```bash
  cd ../../server && JAVA_HOME=/path/to/jdk-25 mvn -o -B -q package -DskipTests
  ```
- Images `postgres:16`, `redis:7-alpine`, `ghcr.io/cerbos/cerbos:0.53.0` available locally.

## Run it

The test suite starts its own disposable estate and tears it down at the end:

```bash
cd examples/identity_scenarios
python3 -m pytest -q tests/                                    # everything except opt-in disruptive checks
AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 python3 -m pytest -q tests/  # also pause Postgres/Redis and restart Axiom (own estate only)
python3 -m pytest -q tests/test_package_c.py                   # one family (CIAM)
python3 -m pytest -q "tests/test_package_c.py::test_example[ciam.b08_consent_grants]"   # one example
python3 -m pytest -q tests/test_safety_offline.py              # offline safety tests, no estate
python3 -m pytest -q tests/test_idp_baseline.py                # the IDP-01..15 capability contracts
python3 -m pytest -q "tests/test_idp_baseline.py::test_idp[idp.idp06_refresh]"   # one capability
.venv/bin/python -m pytest -q tests/test_idp_browser.py        # CIAM/workforce sign-in, consent, logout in Chromium
```

Without the opt-in, the two disruptive tests report as skipped. Treat that as "not run", not as success.

### Browser check for O02 (optional extra)

One Playwright test, `tests/test_o02_browser.py`, drives Axiom's real login page in headless Chromium. It follows the
CSRF form and the S256 PKCE authorization request through to a real loopback callback, then redeems the code with the
HTTP helper. It also checks four things only a browser can show:

- a login form posted from another origin is refused;
- the login page cannot be framed;
- the session cookie is HttpOnly;
- the password never appears in a URL. (The authorization code does arrive in the callback URL, as the code flow
  requires; the test's callback keeps it in memory only and never logs or renders it.)

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test,browser]'   # playwright==1.63.0 (Chromium build 1243)
.venv/bin/python -m playwright install chromium                       # only if that build is not already cached
.venv/bin/python -m pytest -q -rs tests/test_o02_browser.py
```

Without the extra, this test reports as skipped (it is "not run"). It records no trace, video or HAR. A screenshot
is written to `artifacts/` (git-ignored) only on failure. The callback page never shows the code, and failure
messages are scrubbed of code, state, tokens and the password. API-only flows, the CIAM JSON sign-in and the
scenario contracts are deliberately not browser-tested.

To run a single example by hand and read its output, start a long-lived estate:

```bash
python3 -m axiom_cookbook.estate up          # prints the path of a 0600 state file
export AXIOM_COOKBOOK_STATE=<that path>
python3 -m ciam.b08_consent_grants           # prints ALLOWED/DENIED/FACTS/CONSUMER lines, then cleans up its records
python3 -m axiom_cookbook.estate down --state "$AXIOM_COOKBOOK_STATE"
python3 -m axiom_cookbook.estate reap        # removes provably owned leftovers of interrupted runs; reports the rest
```

## Safety rules built in

- **Target guard.** Only loopback targets are accepted, plus an explicit fixture namespace and a write opt-in. Names
  suggesting production, shared or original deployments are refused.
- **One origin.** Bearer tokens, Basic credentials and forms go only to the verified Axiom origin. Absolute URLs to
  other hosts and cross-origin redirects are refused before anything is sent.
- **No secrets in output or URLs.** Credentials are held as `Secret`, and errors and evidence are scrubbed. At
  teardown the suite scans the server logs for token-shaped strings and fails if it finds one. Passwords, client
  secrets and tokens never go in URLs; logout uses a POST form. The authorization code does arrive in the registered
  callback URL, as the code flow requires. The cookbook keeps that URL in memory only and never logs or stores it, and
  your client should do the same.
- **Ownership-proven cleanup.** `down` and `reap` signal a server only if this Python process holds its child handle,
  or `ps` proves it is this exact run's process (same user, own process group, recorded start time, run owner tag on
  its command line). A PID from a state file alone proves nothing. They delete a run directory only if its name,
  owner, mode and ownership marker match that run's state, and remove only containers labelled with that run's id.
  Anything unproven is skipped and reported for manual review, and a live run is left to `down --state`.
- **Owned records only.** Every record lives in a per-run `ckbk-<hex>` namespace and is disabled, revoked, retired
  or suspended through the API at the end. Axiom keeps disabled records for audit; they are reported as residuals
  and never deleted with SQL.

## Simulated parts (read before relying on a result)

- **Customer code delivery is simulated.** Axiom ships no e-mail provider. The cookbook estate enables Axiom's
  loopback-only *local-demo* aid, which returns the verification code to the customer's own request. Axiom refuses to
  start with it on a non-loopback issuer or beside a real provider. A verification in this suite proves the
  verification endpoint, not mailbox delivery. Account recovery is not available.
- **Receivers, gateways and model routes are fixtures** (`axiom_cookbook/receiver.py`). Their "protected actions"
  are list entries. Nothing in this cookbook is Argus or calls a model.
- **Negative-only profiles** (IDP-13 sender constraint, IDP-14 external assertions) prove refusal. Neither is
  selected; no positive federation, partner or proof-of-possession profile exists.
- **Customer self-service authentication** for the consent API uses Axiom's JSON customer sign-in (an Axiom-specific
  extension); the customer's *application* sign-in is the standard browser flow.

## Using the support library in your own code

```python
from axiom_cookbook.http import AxiomHttp
from axiom_cookbook.oauth import Client, client_credentials, exchange, tokens
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import Validator

http = AxiomHttp("https://axiom.example.internal")          # your issuer; credentials never leave this origin
validator = Validator.discover(http)                         # issuer and JWKS pinned to the same origin
svc = Client("orders-svc", Secret(load_secret_from_your_vault(), "client secret"))
token = tokens(client_credentials(http, svc, ["orders.read"]).expect(200)).access_token
claims = validator.access_token(token, "https://orders.example.internal")
```

The target guard in `axiom_cookbook/target.py` exists for the cookbook's disposable estates. Production code should
use its own configuration and secret store.
