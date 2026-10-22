# Local Axiom and Envoy edge — 2026-10-04

## Post-reset installation recorded on 2026-10-04

After the owner reset Docker Desktop Kubernetes, the fresh `docker-desktop` v1.36.4 cluster had only system namespaces.
No earlier Axiom namespace or PVC was deleted by this installation. The observations below were made during that run;
they are not a claim about live cluster state on a later date.

- Built local server image `axiom-server:tenant-scopes-20261004-ba15ab11` from the then-current clone. Image ID
  `sha256:ca45033660ce41bfa43f4ed36ede03b6ee22d145648998a1a0a7ca2118e632b7` matched the running pod.
  This image predates the standards-first delegation-chain change of 2026-10-05.
- Fresh restricted `axiom` namespace: releases `axiom-dependencies` and `axiom` revision 1 deployed; PostgreSQL,
  Redis, Cerbos, Axiom server and Admin Ready; four PVCs Bound. Dependency-connectivity and Axiom smoke Helm tests
  passed. PostgreSQL reported Flyway V41 successful. Runtime and signing Secrets were newly generated.
- Envoy Gateway release `eg` revision 1 used pinned chart v1.9.1. The Gateway was Programmed and four HTTPRoutes were
  `Accepted=True` and `ResolvedRefs=True`. Local TLS certificates had the intended identity and Admin SANs; all
  Services were ClusterIP-only.
- A temporary localhost-only port-forward served readiness `UP`, OIDC discovery with issuer
  `https://identity.meridian.com:8443`, JWKS and Admin HTTPS. Identity HTTP redirected to HTTPS. The local HTTPS
  routes replaced `X-Forwarded-Port` with `8443` so a new OAuth authorize request redirected to the reachable local
  login URL. The port-forward was stopped after testing.
- Through Envoy, an authenticated bootstrap-admin OAuth code/PKCE flow registered `quickstart:invoke` for tenant
  `meridian` (POST 201, identical repeat 200, GET 200). Anonymous GET returned 401 and reserved `axiom:unsafe`
  returned 400. Registration granted no client, person, workload, route or consumer permission. Quickstart identities
  and clients were not provisioned by this test.
- An unlabeled canary resolved Redis's exact service FQDN but could not connect; it was deleted. The authorized
  dependency Helm test was the positive connectivity control.

The login smoke used an in-memory case-insensitive response-header adapter: Envoy lowercased `location` while the
Python cookbook helper copied headers into a case-sensitive dictionary. The unmodified cookbook and Playwright suite
were not run against this Kubernetes release. Local self-signed certificates and hostname mapping remain; arbitrary
consumers are not proven to resolve and trust this issuer.

Scope: `docker-desktop` Kubernetes v1.36.4, fresh cluster with only system namespaces before this installation.
This is a local disposable deployment, not production or a full consumer integration test. The active procedure is
[`deploy/axiom-local-edge/README.md`](../../deploy/axiom-local-edge/README.md); the old `deploy/kind/install.sh` was
not run because it selects an older Axiom image and historical shared-cluster settings.

## Earlier installation (before the owner reset)

- `axiom` namespace: operator-generated runtime and immutable signing Secrets, release `axiom-dependencies` revision
  1 and release `axiom` revision 1. PostgreSQL, Redis, Cerbos, Axiom server and Admin pods were Ready; all four PVCs
  were Bound. Both Helm tests succeeded (`axiom-dependencies-test`, `axiom-smoke`).
- Server pod ran image digest `sha256:0543a0cd8f6161f74c7934c57cc63645b33087d77ffdd5e1f47ff5e17c0791a4`,
  the current Axiom source image `axiom-server:axiom-test-20261003b`. Admin used
  `axiom-admin:phase0-codex-74e7e56`. This was not a fresh image rebuild.
- Envoy Gateway release `eg` revision 1 installed official pinned chart `v1.9.1` (chart digest
  `sha256:91bae9aedb91ab34731e987afe01a3ccf454393015abeca705eea8ee15553e86`), including its Gateway API
  CRDs. `axiom-local-gateway` was Accepted; `gateway-demo/axiom-local-edge` was Programmed; all four Axiom HTTPRoutes
  reported `Accepted=True` and `ResolvedRefs=True`. Both backend Services had ready endpoints.
- Envoy's data-plane Service was `ClusterIP` with ports 80/443, no external IP. Every Service in the cluster was
  `ClusterIP`; no NodePort or LoadBalancer was created. Local self-signed TLS Secrets had only their intended SANs.
- Through a temporary `127.0.0.1`-only port-forward, Envoy served Axiom readiness `{"status":"UP"}`. OIDC discovery
  advertised issuer `https://identity.meridian.com:8443` plus code, refresh, client-credentials and token-exchange
  grants. Admin HTTPS returned 200. Identity HTTP returned 301 to the same hostname on HTTPS port 8443. The
  port-forward was stopped after testing; it is not a persistent public endpoint.
- A disposable canary in `axiom` resolved the exact Redis Service DNS name but could not connect to Redis; its final
  exit code was 0 and log said `Redis access denied to an unlabeled pod.` The authorized dependency Helm test had
  connected to Redis. The canary was deleted. Earlier canary attempts used an `nslookup` search-name check that
  returned nonzero on unrelated NXDOMAIN search candidates despite resolving the service; those attempts were not
  counted as evidence. The final canary used the fully qualified name with a trailing dot.
- A second, temporary `axiom-consumer-probe` namespace tested cross-namespace access. An allow rule matching only
  that namespace and one labeled pod admitted traffic to Axiom server port 8084; the pod fetched readiness, discovery
  with the exact issuer, and JWKS, then exited 0. The temporary allow rule and namespace were deleted afterwards.
  This proves generic in-cluster transport for a selected caller, not a full OAuth flow or Argus integration.

## Limits and recovery

The cluster reports `kindnet`; one local positive/negative connectivity pair does not establish complete
NetworkPolicy enforcement across nodes or a shared-environment security posture. Redis has no password in this
disposable profile. The certificates are self-signed and the public-looking issuer names require local hosts-file
resolution plus a foreground port-forward. The Python cookbook and browser PKCE suite were **not** run against this
Kubernetes release; earlier local cookbook results must not be recast as this deployment's result.

The Axiom Service DNS name is stable for in-cluster HTTP transport, but the advertised HTTPS issuer is not directly
reachable from an arbitrary consumer pod. A consumer library must support separate issuer and transport endpoints,
or a reviewed DNS/TLS design must be added for its actual location. No generic promise of plug-and-play OIDC
connectivity to arbitrary consumers is made here.

If only the app needs rollback, uninstall `axiom` in namespace `axiom` while retaining the dependency release,
operator Secrets and PVCs. For full teardown, follow the exact resource inventory in the local-edge README. Do not
delete the `axiom` namespace or its PVCs as an automatic repair; that destroys this fresh estate's data. No source
commit, push, production deployment or Argus installation was performed by this installation.
