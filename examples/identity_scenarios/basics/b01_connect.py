"""B01 — Connect to a disposable Axiom, verify issuer and discovery, authenticate the provisioning operator.

1. Teaches: how a consumer finds Axiom (OIDC/OAuth discovery) and how the provisioning operator authenticates.
   Population: workforce (the operator is a workforce user).
2. Setup: the estate's one-time bootstrap created the tenant and a root ``platform_admin``; the run context used it
   once to create a ``tenant_admin`` operator (see ``axiom_cookbook/context.py``). No password grant is used anywhere.
3. Records: none beyond the operators created by the run context.
4. Calls: ``GET /.well-known/openid-configuration``, ``GET /.well-known/oauth-authorization-server``,
   ``GET /oauth2/jwks``; operator login = ``GET /oauth/authorize`` → ``POST /login`` (form, CSRF) →
   ``POST /oauth/token`` (``authorization_code`` + S256 ``code_verifier``) with public client ``axiom-admin``.
5. Tokens: the operator receives an ``at+jwt`` access token for audience ``axiom-api`` with ``roles=[tenant_admin]``.
6. Positive: issuer matches the target, the token validates against JWKS. Denials: password grant unsupported;
   the legacy ``/auth/login`` password-to-token endpoint is absent (404; the cookbook profile sets
   ``IAM_AUTH_LEGACY_PASSWORD_LOGIN_ENABLED=false``); the operator cannot assign tenant roles (``platform_admin``
   only); an unauthenticated admin call is 401.
7. Expiry: the operator token expires (``expires_in``) and is bound to an Axiom session.
8. Cleanup: the run context disables the operators at the end (soft delete).
9. Consumer must: pin the issuer, fetch keys from ``jwks_uri``, never accept a token whose ``iss`` differs.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import ADMIN_CLIENT, Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret


def run(ctx: Context) -> Outcome:
    out = Outcome("B01 connect and authenticate the operator")
    oidc = ctx.http.get("/.well-known/openid-configuration").expect(200).json()
    oauth_meta = ctx.http.get("/.well-known/oauth-authorization-server").expect(200).json()
    out.ok(oidc["issuer"] == ctx.target.base_url, "OIDC discovery issuer equals the configured target")
    out.ok(oauth_meta["issuer"] == oidc["issuer"], "OAuth metadata and OIDC discovery agree on the issuer")
    jwks = ctx.http.get("/oauth2/jwks").expect(200).json()
    out.ok(len(jwks["keys"]) >= 1 and all(k.get("kid") for k in jwks["keys"]), "JWKS publishes keyed signing keys")

    tokens = oauth.browser_login(ctx.http, ADMIN_CLIENT, ctx.operator_username, ctx.operator_password,
                                 ("openid", "profile", "email", "roles"))
    claims = ctx.validator.access_token(tokens.access_token, "axiom-api")
    out.ok(claims["sub"] == ctx.operator_username and claims["roles"] == ["tenant_admin"],
           "operator token validates (JWKS, iss, aud, exp, at+jwt) and carries only tenant_admin")
    out.facts.update(operator_token_expires_in=tokens.expires_in, signing_keys=len(jwks["keys"]))

    password_grant = ctx.http.post("/oauth/token", form={"grant_type": "password", "username": ctx.operator_username,
                                                          "password": ctx.operator_password, "client_id": "axiom-admin"})
    out.refused(password_grant.status in (400, 401), "the OAuth password grant is not available")
    legacy = ctx.http.post("/auth/login", json_body={"username": ctx.operator_username,
                                                     "password": ctx.operator_password.reveal()})
    out.refused(legacy.status == 404, "the legacy password-to-token endpoint is switched off in this profile")
    some_role = ctx.http.get("/roles", bearer=tokens.access_token).expect(200).json()[0]["id"]
    escalate = ctx.http.post(f"/users/{ctx.operator_username}/roles", bearer=tokens.access_token,
                             json_body={"roleId": some_role})
    out.refused(escalate.status == 403, "a tenant_admin cannot assign tenant roles (platform_admin only)")
    out.refused(ctx.http.get(ctx.admin_base() + "/applications").status == 401,
                "admin API without a bearer token is 401")
    forged = Secret(tokens.access_token.reveal()[:-4] + "AAAA", "forged token")
    out.refused(ctx.http.get(ctx.admin_base() + "/applications", bearer=forged).status == 401,
                "a token with a broken signature is 401")
    out.consumer_must.append("pin the issuer and validate tokens against jwks_uri; reject any other iss")
    return out


if __name__ == "__main__":
    standalone(run)
