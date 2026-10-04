"""IDP-01 — discovery, metadata and keys (OIDC Discovery 1.0, RFC 8414, RFC 7517).

1. Teaches: how a consumer pins Axiom's issuer, reads its endpoints and JWKS, and checks that what metadata advertises is
   what the issuer actually does. Population: none (public metadata).
2. Setup: none. The consumer configures the expected issuer URL out of band.
3. Records created: one public browser client (to observe live behaviour), cleaned up at the end.
4. Calls: ``GET /.well-known/openid-configuration``, ``GET /.well-known/oauth-authorization-server``, ``GET jwks_uri``,
   ``POST /oauth/token`` with unsupported grants and client authentication methods.
5. Tokens: none issued here; a token forged with a substitute key is presented to show it is rejected.
6. Positive: both documents name the same issuer, equal to the configured one; endpoints and keys live on the issuer's
   origin; grants, client-authentication methods and PKCE methods are exactly the supported set. Denials: an
   unadvertised grant or client-authentication method is refused; a token signed by another key under Axiom's kid and
   issuer is rejected locally and by Axiom.
7. Status: none.
8. Cleanup: the client is disabled through the API.
9. Consumer must: configure the issuer, never follow an issuer named by a token, refresh JWKS on an unknown kid,
   accept only RS256 here, and treat metadata as a capability list, not as proof a feature works for its client.
"""
from __future__ import annotations

import time

import jwt as pyjwt
from urllib.parse import urlsplit

from axiom_cookbook import keys as client_keys, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import InvalidToken
from axiom_cookbook.topology import READ

STANDARD_GRANTS = {"authorization_code", "refresh_token", "client_credentials",
                   "urn:ietf:params:oauth:grant-type:token-exchange"}
CLIENT_AUTH = {"client_secret_basic", "private_key_jwt", "none"}


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-01 discovery, metadata and keys")
    http = ctx.http
    oidc = http.get("/.well-known/openid-configuration").expect(200).json()
    oauth_meta = http.get("/.well-known/oauth-authorization-server").expect(200).json()
    out.ok(oidc["issuer"] == ctx.target.base_url == oauth_meta["issuer"],
           "OIDC discovery and RFC 8414 metadata name the configured issuer")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri", "introspection_endpoint",
                 "revocation_endpoint", "end_session_endpoint", "userinfo_endpoint"):
        http.resolve(oidc[name])  # raises if any endpoint lives on another origin
    out.ok(True, "every advertised endpoint lives on the issuer's origin")
    grants = set(oidc["grant_types_supported"])
    extensions = sorted(grants - STANDARD_GRANTS)
    out.ok(STANDARD_GRANTS <= grants and all(g.startswith("urn:openwolf:") for g in extensions),
           "advertised grants: the four standard grants plus Axiom-namespaced optional extensions only")
    out.ok(set(oidc["token_endpoint_auth_methods_supported"]) == CLIENT_AUTH,
           "client authentication advertised: client_secret_basic, private_key_jwt, none")
    out.ok(oidc.get("code_challenge_methods_supported") == ["S256"], "PKCE: S256 only")
    out.ok("dpop_signing_alg_values_supported" not in oidc and not oidc.get("tls_client_certificate_bound_access_tokens"),
           "no sender-constraint feature is advertised (none is enforced; IDP-13 not selected)")
    out.ok(oidc.get("id_token_signing_alg_values_supported") == ["RS256"], "ID tokens: RS256")
    advertised_scopes = set(oidc.get("scopes_supported") or [])
    out.ok({"openid", "profile", "email", "offline_access", READ} <= advertised_scopes,
           "scopes_supported names the enabled OIDC scopes, offline_access and the approved business scopes")
    jwks = http.get(oidc["jwks_uri"]).expect(200).json()
    out.ok(jwks["keys"] and all(k.get("kid") and k.get("kty") == "RSA" and "d" not in k for k in jwks["keys"]),
           "JWKS publishes keyed RSA public keys only")
    out.facts["worksheet"] = {"issuer": oidc["issuer"], **{k: oidc[k] for k in (
        "authorization_endpoint", "token_endpoint", "jwks_uri", "introspection_endpoint", "revocation_endpoint",
        "end_session_endpoint", "userinfo_endpoint")}, "grant_types_supported": sorted(grants),
        "optional_axiom_extension_grants": extensions,
        "token_endpoint_auth_methods_supported": sorted(oidc["token_endpoint_auth_methods_supported"]),
        "token_endpoint_auth_signing_alg_values_supported": oidc.get("token_endpoint_auth_signing_alg_values_supported"),
        "scopes_supported": oidc.get("scopes_supported")}

    # Live behaviour versus metadata: what is not advertised is refused.
    op = ctx.operator()
    app = ctx.application(op, "meta")
    svc, _ = ctx.service_client(op, app, "meta-svc", [READ])
    for grant in ("password", "urn:ietf:params:oauth:grant-type:device_code",
                  "urn:ietf:params:oauth:grant-type:jwt-bearer"):
        r = http.post("/oauth/token", basic=svc.basic(), form={"grant_type": grant, "scope": READ})
        out.refused(r.status in (400, 401) and "access_token" not in r.text, f"unadvertised grant {grant} is refused")
    post_auth = http.post("/oauth/token", form={"grant_type": "client_credentials", "scope": READ,
                                                "client_id": svc.client_id, "client_secret": svc.secret})
    out.refused(post_auth.status == 401, "client_secret_post (not advertised) is refused")

    # A token signed with a substitute key under Axiom's issuer and kid is rejected.
    forger = client_keys.generate("RS256")
    forged = pyjwt.encode({"iss": oidc["issuer"], "sub": "anyone", "aud": app["audience"], "iat": int(time.time()),
                           "exp": int(time.time()) + 60, "scope": READ}, forger.private_key, algorithm="RS256",
                          headers={"kid": jwks["keys"][0]["kid"], "typ": "at+jwt"})
    try:
        ctx.validator.access_token(Secret(forged, "forged token"), app["audience"])
        locally = False
    except InvalidToken:
        locally = True
    out.refused(locally, "a token signed by a substitute key under Axiom's kid fails local validation")
    status = oauth.introspect(http, svc, Secret(forged, "forged token"))
    out.refused(status.get("active") is False, "Axiom reports the substituted-key token inactive")
    # Every advertised endpoint behaves: UserInfo answers for both populations' application tokens, not for software.
    from axiom_cookbook import ciam
    web, _ = ctx.interactive_client(op, app, "meta-web", ["profile", "email", READ])
    shop, _ = ctx.interactive_client(op, app, "meta-shop", ["profile", "email", READ], population="CUSTOMER")
    role = ctx.app_role(op, app, "reader", {READ: "allow"})
    person, pw = ctx.workforce_user(op, "uma")
    ctx.membership(op, app, person, role["id"])
    customer = ciam.verified(ctx, op, "uri")
    userinfo_path = urlsplit(oidc["userinfo_endpoint"]).path
    for label, client, user, password, sub in (("workforce", web, person, pw, person),
                                               ("customer", shop, customer.email, customer.password, customer.id)):
        t = oauth.browser_login(http, client, user, password, ("openid", "email"))
        info = http.get(userinfo_path, bearer=t.access_token)
        out.ok(info.status == 200 and info.json().get("sub") == sub, f"UserInfo answers for a {label} application token")
    software = oauth.tokens(oauth.client_credentials(http, svc, [READ]).expect(200)).access_token
    out.refused(http.get(userinfo_path, bearer=software).status in (401, 403), "UserInfo refuses a software token (no user)")
    out.consumer_must += ["pin the issuer and discovery URL in configuration; reject tokens from any other iss",
                          "validate against jwks_uri; refetch on an unknown kid; never accept alg=none",
                          "treat Axiom-namespaced grants as optional extensions, not part of the portable contract"]
    return out


if __name__ == "__main__":
    standalone(run)
