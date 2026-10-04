"""O02 — Workforce authorization code with S256 PKCE, state and nonce.

1. Teaches: how a browser application signs a workforce user in. Population: workforce.
2. Setup: operator creates an application, its public client (exact redirect URI) and a member user.
3. Records: application, public client, application role, membership, user.
4. Calls: ``GET /oauth/authorize`` (``code_challenge_method=S256``, ``state``, ``nonce``) → login form →
   ``POST /oauth/token`` ``grant_type=authorization_code`` with ``code_verifier``.
5. Tokens: an access token for the application's audience and an ID token whose ``aud`` is the client and whose
   ``nonce`` echoes the request.
6. Positive: tokens issued and validated; ``state`` and ``nonce`` round-trip. Denials: missing PKCE (400); wrong
   verifier, redirect mismatch and code replay at the token endpoint (``invalid_grant``); disabled client.
7. Expiry: the authorization code is single-use; the access token expires per ``expires_in``.
8. Cleanup: client/application disabled, user disabled.
9. Consumer must: generate a fresh verifier/state/nonce per login and check state and nonce on return.
"""
from __future__ import annotations

import secrets

from axiom_cookbook import oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret


def run(ctx: Context) -> Outcome:
    out = Outcome("O02 workforce authorization code + PKCE")
    op = ctx.operator()
    app = ctx.application(op, "workspace")
    web, web_record = ctx.public_client(op, app, "workspace-web", ["reports.read"])
    role = ctx.app_role(op, app, "user", {"reports.read": "allow"})
    dana, password = ctx.workforce_user(op, "dana")
    ctx.membership(op, app, dana, role["id"])
    scopes = ("openid", "reports.read")

    verifier, challenge = oauth.pkce_pair()
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    code, _ = oauth.authorize_code(ctx.http, web, dana, password, scopes, challenge, state, nonce)
    out.refused(oauth.redeem_code(ctx.http, web, code, Secret("x" * 50, "wrong verifier")).oauth_error() == "invalid_grant",
                "a wrong PKCE verifier is refused")
    code, _ = oauth.authorize_code(ctx.http, web, dana, password, scopes, challenge, state, nonce)
    out.refused(oauth.redeem_code(ctx.http, web, code, verifier, redirect_uri="http://127.0.0.1:9/elsewhere")
                .oauth_error() == "invalid_grant", "a redirect URI differing from the authorization request is refused")
    code, session = oauth.authorize_code(ctx.http, web, dana, password, scopes, challenge, state, nonce)
    issued = oauth.tokens(oauth.redeem_code(ctx.http, web, code, verifier).expect(200))
    # Inside the signed-in browser session: the registered redirect URI must match exactly, and PKCE is mandatory.
    base = {"response_type": "code", "client_id": web.client_id, "scope": "openid", "state": "s"}
    wrong_redirect = ctx.http.get("/oauth/authorize", session=session, headers={"Accept": "text/html"},
                                  params={**base, "redirect_uri": web.redirect_uri + "/x", "code_challenge": challenge,
                                          "code_challenge_method": "S256"})
    out.refused(wrong_redirect.status == 400 and "code=" not in wrong_redirect.headers.get("Location", ""),
                "an authorization request with an unregistered redirect URI is refused (no code)")
    no_pkce = ctx.http.get("/oauth/authorize", session=session, headers={"Accept": "text/html"},
                           params={**base, "redirect_uri": web.redirect_uri})
    out.refused(no_pkce.status == 400 and "code=" not in no_pkce.headers.get("Location", ""),
                "an authorization request without S256 PKCE is refused (no code)")
    out.facts.update(wrong_redirect_status=wrong_redirect.status, missing_pkce_status=no_pkce.status)
    out.refused(oauth.redeem_code(ctx.http, web, code, verifier).oauth_error() == "invalid_grant",
                "an authorization code cannot be redeemed twice")
    claims = ctx.validator.access_token(issued.access_token, app["audience"])
    id_claims = ctx.validator.id_token(issued.id_token, web.client_id, nonce=nonce)
    out.ok(claims["sub"] == dana and claims.get("identity_kind") == "workforce",
           "access token: sub is the person, audience is the application")
    out.ok(id_claims["sub"] == dana, "ID token: audience is the client and the nonce round-trips")
    out.facts.update(expires_in=issued.expires_in, acr=claims.get("acr"), has_auth_time="auth_time" in claims)

    ctx.http.delete(f"{ctx.admin_base()}/applications/{app['id']}/clients/{web_record['id']}", bearer=op).expect(204)
    try:
        oauth.browser_login(ctx.http, web, dana, password, scopes)
        disabled_login = True
    except oauth.LoginFailed:
        disabled_login = False
    out.refused(not disabled_login, "a disabled client cannot start a login")
    out.consumer_must.append("bind state and nonce to the browser session and verify both on return")
    return out


if __name__ == "__main__":
    standalone(run)
