# MCP client sign-in support

Implementation branch: `codex/axiom-mcp-clients`, based on `c292924`. Axiom only; no Argus, control-plane, deployment, or live Kubernetes changes. The original shared checkout and its uncommitted work are preserved.

## Trust and tenant selection

A CIMD URL identifies an app vendor, not a person or a tenant. Axiom stores a separate approval and internal OAuth registration for each tenant application. The external client ID in access tokens and ID tokens remains the exact CIMD URL. Tokens retain the selected application's audience, tenant, population, and person authority.

An initial CIMD authorization request must supply an explicit `redirect_uri` and one `resource` equal to the approved application's audience. The URL and resource must select exactly one active approval across the issuer; ambiguous resources are refused before fetching metadata. A missing resource is refused. This follows MCP's resource-bound flow and avoids guessing a tenant from a shared vendor ID.

Code redemption, refresh, and consent select the internal registration from the server-stored grant, not a newly supplied resource. The existing resource guard then rejects any attempt to change its audience. Internal synthetic client IDs are refused as protocol client IDs. Authorization, consent, and minting still enforce the existing person membership and population boundaries.

Approving the same vendor in another application creates an independent approval. Removing one approval disables its registration and revokes sessions of that application and client. It leaves other applications' approvals and sessions active. Reapproval creates a new registration, so an old refresh family cannot be revived.

## Admin API

Use the existing authenticated tenant/platform administrator API:

- `POST /admin/tenants/{tenantId}/applications/{applicationId}/trusted-clients`
- `GET /admin/tenants/{tenantId}/applications/{applicationId}/trusted-clients`
- `PUT /admin/tenants/{tenantId}/applications/{applicationId}/trusted-clients/{approvalId}` (full replacement body plus `expectedRevision`; returns a new approval generation)
- `DELETE /admin/tenants/{tenantId}/applications/{applicationId}/trusted-clients/{approvalId}?expectedRevision={revision}`

Example POST body for ChatGPT (the tenant must already approve the business scope):

```json
{
  "clientId": "https://chatgpt.com/oauth/client.json",
  "redirectUris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
  "tokenEndpointAuthMethod": "private_key_jwt",
  "scopes": ["openid", "argus:read"],
  "refreshTokens": true,
  "population": "WORKFORCE",
  "displayName": "ChatGPT",
  "refreshTokenTtlSeconds": 604800
}
```

The response contains the approval ID, revision, admin-controlled display name, redirects, authentication method, scopes, access and refresh lifetimes, population, and status. PUT retires the old approval, revokes its sessions and authorizations, and creates a new persisted registration; old codes, refresh families, and consents cannot be revived by editing or reapproval. Adding an approval makes no outbound request. No vendor is seeded automatically. The accompanying `control-plane-chatgpt-cimd-seed.patch` corrects the reviewed control-plane seed to `private_key_jwt`; it is a handoff artifact and has not been applied to the excluded repository. Additions and deletions use required audit writes in the admin transaction. Deletion rejects stale revisions and cross-tenant callers.

`refreshTokens` defaults to true for an explicit trusted-client approval. `refreshTokenTtlSeconds` is optional. `population` defaults to the existing workforce posture; a customer approval must explicitly select `CUSTOMER`.

Axiom currently has no application-level scope field. If `scopes` is omitted, the default is `openid profile email`, plus scopes already approved for the application's active interactive clients, with `offline_access` added only when refresh is enabled. An application without existing clients receives identity scopes only; business scopes must be granted explicitly. All scopes still pass the existing vocabulary checks. OAuth requests without `openid` work; that scope is required in the interactive registration, not in every request.

## Public refresh tokens

Static `PUBLIC_BROWSER` registrations opt in with `refreshTokens: true`. Existing registrations and omitted/false values keep the closed default. A client without opt-in still cannot register or request `offline_access` and receives no refresh token.

Issuance requires both the refresh grant and granted `offline_access`. Public refresh requests identify the client with `client_id`; presenting a secret/assertion does not fall back to this path. Spring still checks the refresh token's internal registered-client binding. Each successful refresh returns a new opaque token; its expiry remains the family's initial expiry. Default public/trusted lifetime is 30 days, bounded by the existing deployment refresh maximum (default 30 days, configurable up to 90). An explicitly shorter lifetime is supported down to 60 seconds.

Existing Redis redemption serialization applies to public refreshes. A spent token presented by its authenticated client withdraws the family and durable session and emits `REFRESH_FAMILY_WITHDRAWN`. Wrong-client presentations cannot withdraw another client's family. Expired, spent, and withdrawn tokens return `invalid_grant`. Confidential-client issuance and lifetime policy remain unchanged.

## Metadata and key retrieval

- Unknown or inactive approvals never trigger a metadata fetch.
- HTTPS on port 443 with a path, exact URL comparison, no user information, fragments, queries, raw or encoded dot segments, Unicode URL spellings, or IP literals. These are intentionally conservative URL restrictions.
- The connection uses the exact DNS answers checked for that connection. Private, loopback, link-local, multicast, special-use, IPv4-mapped/transition, and known cloud metadata addresses are refused. Federation network exceptions do not apply. Mixed public/private DNS answers are refused.
- No HTTP redirects, retries, cookies, compression, or ambient proxy configuration. Normal TLS hostname/certificate verification remains enabled.
- Five-second total fetch deadline, including a caller bound around stalled DNS; at most 20 outstanding workers/connections. Workers that remain blocked retain their capacity slot until they finish. HTTP headers and body size are bounded. An oversized stream is aborted before closing so connection cleanup cannot drain an unbounded body.
- HTTP 200 and `application/json` or an `application/*+json` media type are required; body cap 65,536 bytes. Duplicate JSON keys, trailing objects, malformed documents, shared secrets, and inline CIMD key sets are refused. This implementation uses delegated `jwks_uri` for private-key clients.
- Required MCP document fields and authorization-code support are checked. Redirects are the intersection of the document and admin approval; optional document scopes and grants can narrow the approval. The authentication method must match exactly. The document cannot add tenant authority, scopes, redirects, or grants.
- All registered-client repository lookups are storage-only. Metadata is read explicitly for a fresh authorization request; keys are loaded explicitly when verifying a signed client assertion. Public refresh, consent management, introspection and logout do not depend on vendor HTTP. JWKS uses the same hardened transport. Existing `ClientAssertionKeys` checks allow bounded sets of public RSA/RS256 or P-256/ES256 keys. Existing assertion issuer, subject, audience, expiry, maximum lifetime, and single-use `jti` checks remain in force. Keys and the metadata authorizing their delegation must be revalidated within five minutes, with no stale-key or stale-delegation fallback. An unknown `kid` may trigger one forced JWKS refetch per key URL per 30 seconds; a newly published key can work immediately, and removed keys cannot be recovered from a day-old cache.
- Valid documents are cached per node in a bounded cache. Freshness follows `max-age`, within five minutes to 24 hours, reduced by `Age`; `no-store`, `no-cache`, and `max-age=0` disable caching. This 24-hour stale policy applies to authorization metadata, never assertion keys or key delegation. A network/server failure can use the last validated copy until 24 hours from its original retrieval. Retry suppression never extends that cutoff. Invalid metadata, private DNS, redirects, and client HTTP errors clear the cached copy. Errors are never cached. Each attempted fetch failure emits a tenant-qualified audit event. Updating or removing an approval evicts its known metadata/key cache entries.

Every CIMD authorization requires a fresh approval, including requests with remembered consent, `prompt=none`, and `openid` alone. The authorization ceremony ignores remembered permissions both when showing the screen and when processing its decision; an empty/denied submission cannot inherit old permissions. Consent shows the administrator's name for the app, a secondary escaped document name, the identity host, and the actual callback hostname and approved hosts. Control and bidi characters are removed and visible names are capped at 80 characters. A local callback displays an additional warning. Successful authorizations emit `CIMD_SIGN_IN`; successful refresh rotation emits `CIMD_REFRESH` with grant type and authorization ID, never token values.

## Standards verification and proposal corrections

- [MCP authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) recommends CIMD and makes dynamic registration optional. Supporting CIMD does not require a DCR endpoint. Axiom advertises CIMD and `none`, and continues to expose no DCR endpoint.
- [CIMD draft 02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02) remains an Internet-Draft; MCP 2025-11-25 references draft 00. Exact client ID matching, credential restrictions, redirect validation, and no fetch redirects are checked explicitly rather than treating the draft as a finalized RFC.
- [ChatGPT's published document](https://chatgpt.com/oauth/client.json), checked on 2026-10-28, declares `private_key_jwt` and delegates to [its JWKS](https://chatgpt.com/oauth/jwks.json). Its additional supported-methods list includes `none`; Axiom nevertheless pins the declared method and the administrator's approval. A `none` approval is not treated as permission to downgrade that declaration. The supplied Claude endpoint contents could not be retrieved through the research tool and are not claimed as live-verified here. Codex/Factory URLs remain unspecified and unseeded.
- [Spring 1.5.8 refresh generation](https://github.com/spring-projects/spring-authorization-server/blob/1.5.8/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/token/OAuth2RefreshTokenGenerator.java) deliberately suppresses public authorization-code refresh issuance. [Its public authentication converter](https://github.com/spring-projects/spring-authorization-server/blob/1.5.8/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/web/authentication/PublicClientAuthenticationConverter.java) handles code redemption with PKCE, not ordinary public refresh identification. Both need the explicit gated extensions implemented here.
- [RFC 8252 sections 7.3/8.3](https://datatracker.ietf.org/doc/html/rfc8252) permit variable loopback ports and recommend IP literals over `localhost`. Spring already supports loopback-IP port variation. Axiom adds strict matching for `127.0.0.1`, `[::1]`, and explicit `localhost` compatibility, ignoring only the port of HTTP loopback redirects. Host, raw path, raw query, and scheme stay exact. This is not a general redirect wildcard.
- [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) requires issuer identification on authorization responses, including error redirects that can safely be returned to a validated callback. Axiom now advertises it and includes configured `iss` on those redirects. Invalid/untrusted callbacks remain local errors, without redirecting to attacker input.
- [RFC 9700 section 4.14](https://www.rfc-editor.org/rfc/rfc9700) requires replay protection for public refresh tokens through rotation or sender constraints. Axiom uses rotation, client binding, existing cross-instance redemption serialization, absolute family lifetime, and replay withdrawal.

## Validation and remaining acceptance

**Final post-review result: 538 tests passed (479 unit tests and 59 integration tests), zero failures, errors or skips. All 32 expanded MCP integration cases passed.** The earlier pre-review run passed 517 tests. Review fixes add repeated-consent denial, fresh-start persistence, private-key rotation/cache expiry, metadata-independent lookups, customer consent management, and approval replacement checks. The regenerated JSON evidence records the final post-review counts and source hashes.

The test groups and exact final counts are recorded in `mcp-client-support-test-results-2026-10-28.json` beside this note. `McpClientSupportIT` uses Axiom's actual HTTP security filters and admin/code/consent/token endpoints with disposable PostgreSQL and Redis; only outbound metadata/JWKS retrieval is stubbed. Transport tests separately exercise response status/type, streaming size limits, address policy, and deadline behavior.

These checks cover all ten requested groups plus tenant/application isolation, resource substitution, expired tokens, unexpected credentials, concurrent refresh, stale revision deletion, reapproval, scoped revocation, long client URLs, and ambiguous resources. Existing issuer, delegation-chain, and issuance-boundary suites check regressions in confidential clients and exchange authority.

Live Azure acceptance, real Claude/ChatGPT sign-in, real vendor signatures against the deployed issuer, and the hour-later refresh check remain separate acceptance steps. No deployment, image publication, push, merge, or live tenant registration was performed. An issuer cannot currently disambiguate identical MCP resource audiences in different tenants for the same shared client URL; those requests fail closed, and such deployments need distinct resource audiences or a future explicit tenant-routing design.

Isolated CIMD fixtures cover workforce and customer sign-in, customer self-service consent listing/withdrawal by opaque registration ID, and cross-customer/tenant rejection. A fresh Axiom application instance starts on a random loopback port against the same disposable database, Redis and signing keys and successfully refreshes a previously issued public CIMD token during a vendor outage. This is a fresh-application proof, not a live Azure restart. Customer consent management returns `consentId` and `applicationId`; shared URLs use `DELETE /ciam/tenants/{tenantId}/customers/{customerId}/oauth-consents/registrations/{consentId}`. Stateless resource servers that validate JWTs locally observe revocation according to their own session/introspection integration and access-token expiry; refresh-family withdrawal does not remotely erase already issued JWTs.

Strict refresh replay withdrawal remains intentional: a lost refresh response followed by a retry can require sign-in again. No retry grace window is introduced. Live refresh acceptance must wait over 65 minutes (or deliberately configure a short access lifetime), verify a tool call succeeds, and correlate a `CIMD_REFRESH` event with a changed refresh token without publishing token values. Capture ChatGPT's stable client ID and callback, show the local callback warning, remove an approval and confirm `invalid_grant`, and confirm an unapproved URL triggers no fetch.

See [review resolutions](mcp-client-review-resolutions-2026-10-28.md) for every blocker, should-fix and small finding, including decisions that differ from the review and outstanding external acceptance. JWT client assertions follow [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523); resource binding follows [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707).
