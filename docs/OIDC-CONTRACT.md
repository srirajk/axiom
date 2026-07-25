# Axiom OIDC-Only Identity Contract

**Status:** Accepted north star  
**Scope:** Axiom as the OpenID Provider for connected applications and as the relying party for a
customer's workforce OpenID Provider  
**Excluded:** SAML, implicit grant, resource-owner password grant, open dynamic client registration

## 1. Product model

Axiom has two explicit OIDC relationships:

```text
Customer workforce OpenID Provider
        │  OIDC federation
        ▼
      Axiom
        │  Axiom-issued OIDC/OAuth tokens
        ├── Probata
        ├── Orchestrator
        ├── Fondue
        └── Other registered applications
```

- The customer provider authenticates the workforce user.
- Axiom links that upstream identity to one stable Axiom principal using exact `(issuer, subject)`.
- Axiom owns application membership, application roles, typed attributes and entitlement revision.
- Connected applications trust Axiom's issuer, discovery document and JWKS.
- Applications never need to understand each customer's upstream provider.

## 2. Deployment and issuer

1. One customer organization is served by one Axiom deployment.
2. Each environment has a separate deployment and a separate canonical HTTPS issuer.
3. The issuer is immutable after initialization and matches tokens and discovery metadata exactly.
4. Issuer aliases, request-derived issuers and forwarded-host inference are forbidden.
5. The public issuer, allowed Admin origin and callback origins are explicit deployment configuration.
6. Internal service addresses are never emitted in public discovery metadata.

## 3. Required discovery and endpoints

Axiom publishes standards-compatible metadata at:

- `/.well-known/openid-configuration`
- the advertised authorization endpoint;
- the advertised token endpoint;
- the advertised `jwks_uri`;
- the advertised UserInfo endpoint;
- the advertised token revocation endpoint;
- the advertised token introspection endpoint for authorized resource servers; and
- the advertised RP-initiated logout endpoint.

Discovery declares only capabilities Axiom actually supports, including:

- `response_types_supported = ["code"]`;
- supported grant types;
- `code_challenge_methods_supported = ["S256"]`;
- supported scopes and claims;
- supported subject type;
- supported ID-token and access-token signing algorithms; and
- supported client-authentication methods.

Metadata, endpoint paths and issuer are contract-tested together. A partially configured endpoint is
not advertised.

## 4. Application and client registration

### Public browser client

- Authorization Code only.
- No client secret.
- S256 PKCE required on every authorization.
- Transaction-bound `state` and `nonce`.
- Exact registered HTTPS redirect and post-logout redirect URIs.
- Loopback HTTP is allowed only for an explicitly supported local/native development profile.
- No wildcard hosts, wildcard paths, fragments or open redirectors.

### Confidential interactive client

- Authorization Code with client authentication.
- S256 PKCE also required.
- Secret or private-key client authentication is explicitly configured.
- Redirect and logout URIs use the same exact-match rules.

### Confidential service client

- Client Credentials only.
- No redirect URI.
- One application and one resource audience.
- Approved machine scopes only.
- Tenant/organization binding is stored with the client and never accepted from a token request.

### Unsupported

- Implicit grant.
- Resource-owner password grant.
- Arbitrary browser-selected scopes, audiences, grants or token lifetimes.
- Open dynamic client registration.
- A public client containing a secret.

## 5. Authorization request security

1. `client_id` resolves to one active persisted client and application.
2. `redirect_uri` uses exact string comparison against the registered value.
3. `response_type` must be `code`.
4. `scope` is a subset of the client's approved scopes and includes `openid` for OIDC.
5. Public and interactive clients provide S256 `code_challenge`; `plain` and missing PKCE deny.
6. `state` and `nonce` are high-entropy, transaction-specific and bound to the initiating browser
   session.
7. Authorization codes are one-time, short-lived, client-bound, redirect-bound and PKCE-bound.
8. Consent is a client/application policy. Suppressed consent is allowed only for trusted,
   administrator-approved first-party clients.
9. Error redirects are sent only to an already validated redirect URI and never include secrets.

## 6. Tokens and claims

### JWT access token

- Signed asymmetric JWT with `typ = "at+jwt"`.
- Required claims:
  - `iss`;
  - `sub`;
  - `aud`;
  - `exp`;
  - `iat`;
  - `jti`;
  - `client_id`; and
  - `scope`.
- Axiom claims:
  - immutable organization/deployment identifier;
  - application identifier;
  - application membership identifier;
  - application-scoped roles;
  - approved typed attributes;
  - entitlement revision; and
  - authentication context (`auth_time`, `acr`, `amr`) for user grants.
- `aud` is derived from the registered application/resource. Caller input cannot create an arbitrary
  audience.
- Service-client `sub` is the stable service-principal/client subject, never a user-controlled value.
- Email, display name and mutable usernames are never authorization identifiers.

### ID token

- `iss`, `sub`, `aud`, `exp`, `iat` and transaction `nonce` are present and validated.
- `aud` identifies the client; `azp` is validated when required.
- The ID token is for client authentication/session establishment and is not accepted as an API access
  token.

### Refresh token

- Issued only to explicitly approved clients.
- Bound to the client, subject, granted scopes, resources and authorization grant.
- Public-client refresh tokens rotate on every use.
- Reuse of an invalidated refresh token revokes the whole token family and creates a security event.
- Absolute and inactivity lifetimes are configured and bounded.
- Logout, principal disablement, membership disablement, client disablement and detected replay revoke
  the applicable refresh-token family.

## 7. JWKS, `kid` and signing-key lifecycle

`kid` means **key ID**. It is a public, case-sensitive identifier used to select the correct public key
during signing-key rollover.

1. Every signing key has a unique collision-resistant `kid`.
2. Every JWT header contains `alg`, `typ` and `kid`.
3. The public JWKS contains public material only:
   - `kty`;
   - public key parameters;
   - `use = "sig"` or consistent `key_ops`;
   - `alg`; and
   - `kid`.
4. Private key material is never exposed by JWKS, logs, Admin APIs, backups or seed files.
5. Production private keys are held by a KMS/HSM or encrypted with envelope encryption. PostgreSQL
   stores key metadata, lifecycle state and encrypted references/material, not plaintext private keys.
6. Signing-key states are:
   - generated;
   - published;
   - current signer;
   - retiring/verifying;
   - retired; and
   - emergency revoked.
7. Normal rotation:
   - create the new key;
   - publish it in JWKS before first use;
   - promote it atomically as the signer;
   - retain the previous public key through maximum token lifetime plus clock skew and cache allowance;
   - retire it only after no valid token can reference it.
8. At most one normal current signer exists, while multiple public verification keys may overlap.
9. Missing/corrupt key state fails startup closed. Runtime does not silently generate a new issuer key.
10. Every generation, publication, promotion, retirement and emergency revocation is audited.
11. Applications cache discovery/JWKS using HTTP cache guidance. On an unknown `kid`, they refresh JWKS
    once and retry validation; they never accept an unverified token.

## 8. Token validation contract for applications

Every resource server:

1. obtains issuer and `jwks_uri` from trusted deployment configuration/discovery;
2. allows only configured asymmetric algorithms;
3. selects the public key by `kid`;
4. verifies the signature;
5. requires the access-token `typ`;
6. compares `iss` exactly;
7. verifies its exact audience is present in `aud`;
8. validates `exp`, `nbf` when present, and reasonable `iat` with bounded clock skew;
9. validates `client_id`, scopes and application/organization binding;
10. validates membership and entitlement revision through the live context/revocation contract for
    high-risk operations; and
11. rejects malformed, unsigned, wrong-key, wrong-algorithm, wrong-issuer, wrong-audience, expired,
    premature and disabled-subject tokens without disclosure.

## 9. Upstream customer OIDC federation

Each configured upstream provider records:

- exact issuer;
- discovery endpoint;
- authorization, token, UserInfo and JWKS endpoints learned from validated discovery;
- Axiom's upstream client ID and encrypted credential/reference;
- exact callback URI;
- requested scopes;
- allowed signing algorithms;
- required claims;
- claim mappings;
- required authentication context/assurance;
- metadata/JWKS cache state;
- enabled/disabled state; and
- last validation and health result.

Validation rules:

1. HTTPS and exact issuer matching are mandatory outside local development.
2. Discovery's issuer must exactly equal the configured issuer.
3. Upstream ID-token signature, `kid`, algorithm, issuer, Axiom client audience, expiry, issued-at and
   nonce are validated.
4. The local identity link is keyed by `(provider_id, issuer, sub)`.
5. Email-only, username-only and display-name-only linking are forbidden.
6. An unknown upstream subject may be quarantined for explicit linking or approved JIT creation, but
   receives no application membership automatically.
7. A disabled provider/link/principal fails closed.
8. Metadata and JWKS are cached for bounded periods. Unknown `kid` triggers one controlled refresh.
   Expired metadata or an unverifiable signature fails authentication; a stale cache never weakens
   cryptographic validation.
9. Provider secrets are encrypted, rotatable, shown only when created where applicable, and never
   returned by read APIs.

## 10. Sessions, logout, revocation and introspection

- Axiom maintains a user-visible and administrator-visible session inventory.
- RP-initiated logout validates the ID-token hint and exact registered post-logout URI.
- Back-channel logout is supported for registered applications that require coordinated logout.
- Logout invalidates the Axiom browser session and applicable refresh-token family.
- Token revocation follows non-disclosing semantics.
- Introspection is available only to authenticated, authorized resource servers and returns only the
  caller's permitted token context.
- Principal, application, client, membership, upstream link or emergency-key disablement takes effect
  at the live authorization/context boundary without waiting for a previously issued token to expire.

## 11. Secret lifecycle

- Client and SCIM secrets are generated from cryptographically secure random material.
- A plaintext secret is returned exactly once.
- Storage uses a strong one-way password hash where verification is sufficient.
- Secrets needed for outbound calls use KMS-backed envelope encryption.
- Rotation supports a short explicit overlap where operationally required.
- Secret expiry, last-used time, rotation due date and failed-use telemetry are visible without exposing
  the secret.
- Revocation is immediate and audited.

## 12. Operational and conformance requirements

- Health distinguishes issuer, signing-key, database, OAuth-state, upstream-provider, SCIM and policy
  runtime readiness.
- Audit records application, client, principal, session, provider, key, credential and entitlement
  revision without logging tokens or secrets.
- Authentication, token, discovery, JWKS and SCIM endpoints have bounded rate limits and abuse
  telemetry.
- Time is synchronized; allowed clock skew is explicit and tested.
- Backup/restore proves database, OAuth state, encrypted signing-key references/material and active
  policy revision.
- Conformance includes:
  - OpenID Provider discovery/core behavior;
  - public-client Authorization Code + S256;
  - confidential service-client token issuance;
  - exact redirect and issuer checks;
  - key rollover with overlapping JWKS;
  - refresh-token rotation/reuse detection;
  - logout/revocation;
  - upstream provider key rollover/outage; and
  - restart and restore.

## 13. Seed and migration boundary

- Flyway owns schema, constraints and indexes only.
- Signing private keys, client secrets and upstream provider secrets are never seed data.
- Baseline applications, roles, attribute schemas and platform policies are created by idempotent
  service/CLI seed runners.
- Reference OIDC providers use non-production fixtures and are never enabled by a production seed.
- Policy content is activated through the same approval and PostgreSQL/Cerbos publication path used in
  normal administration.

## 14. Normative baseline

- OpenID Connect Core 1.0 and Discovery 1.0.
- OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.
- RFC 7517 (JWK), RFC 7519 (JWT) and RFC 9068 (JWT access-token profile).
- RFC 7636 (PKCE), RFC 7009 (revocation), RFC 7662 (introspection) and RFC 9700 (OAuth 2.0 Security BCP).

