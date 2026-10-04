"""IDP-02 — browser sign-in for workforce and CIAM: authorization code + S256 PKCE, state and OIDC nonce
(OIDC Core 1.0, RFC 7636, RFC 6749 section 4.1).

1. Teaches: the same standard code flow for two separate populations. Workforce people sign in through a
   workforce client (Axiom's ``/login`` page); customers through a customer-facing client (``/login/customer``).
2. Setup (provider-specific setup adapter, tenant_admin): an application, a workforce public client, a customer public
   client, a workforce member, and a customer provisioned by the administrator and verified by the customer
   (verification delivery is the loopback-only local-demo aid: simulated delivery, labelled).
3. Records: application, two clients, a workforce user and membership, a customer. Returned ids: client ids, the
   customer id (= the customer token's ``sub``).
4. Calls: ``GET /oauth/authorize`` → login page (CSRF form, real cookie session) → ``POST`` the form → resumed
   ``/oauth/authorize`` → redirect with ``code`` and ``state`` → ``POST /oauth/token`` (code, verifier, redirect URI).
5. Tokens: a code (single use), an access token (audience = the application) and an ID token (audience = the client,
   ``nonce`` echoed). The browser session is separate from the tokens.
6. Positive: both populations obtain validated tokens; the ID token validates for the client with the nonce. Denials:
   wrong verifier, redirect mismatch, code replay, missing PKCE, unregistered redirect, disabled client; workforce
   credentials on the customer page and customer credentials on the workforce page; an unverified customer; a signed-in
   customer cannot obtain a workforce code (and vice versa) with the same browser session.
7. Status: replaying a code also ends the session of the first redemption (its tokens introspect inactive).
8. Cleanup: clients and application disabled, user disabled, customer suspended (no delete API: residuals reported).
9. Consumer must: generate verifier/state/nonce per login, check state before redeeming and nonce on the ID token,
   keep the code and verifier out of logs and URLs it controls, and use the client of the right population.
"""
from __future__ import annotations

import secrets

from axiom_cookbook import ciam, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.topology import READ


def _code(http, client, user, password, scopes, session=None):
    verifier, challenge = oauth.pkce_pair()
    state, nonce = secrets.token_urlsafe(12), secrets.token_urlsafe(12)
    code, session = oauth.authorize_code(http, client, user, password, scopes, challenge, state, nonce, session=session)
    return code, verifier, nonce, session


def _fails(fn) -> bool:
    try:
        fn()
        return False
    except (oauth.LoginFailed, oauth.ConsentRequired):
        return True


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-02 browser sign-in (workforce and CIAM)")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    app = ctx.application(op, "signin")
    staff_web, _ = ctx.interactive_client(op, app, "staff-web", ["profile", "email", READ])
    shop_web, shop_record = ctx.interactive_client(op, app, "shop-web", ["profile", "email", READ],
                                                   population="CUSTOMER")
    out.ok(shop_record["population"] == "CUSTOMER" and shop_record["pkceRequired"], "customer client registered: CUSTOMER, PKCE")
    role = ctx.app_role(op, app, "reader", {READ: "allow"})
    person, person_pw = ctx.workforce_user(op, "pat")
    ctx.membership(op, app, person, role["id"])
    customer = ciam.verified(ctx, op, "carol")

    for label, client, user, password in (("workforce", staff_web, person, person_pw),
                                          ("customer", shop_web, customer.email, customer.password)):
        code, verifier, nonce, _ = _code(http, client, user, password, ("openid", "email", READ))
        t = oauth.tokens(oauth.redeem_code(http, client, code, verifier).expect(200))
        access = v.access_token(t.access_token, app["audience"])
        idt = v.id_token(t.id_token, client.client_id, nonce)
        expected_sub = person if label == "workforce" else customer.id
        out.ok(access["sub"] == expected_sub == idt["sub"] and access["client_id"] == client.client_id,
               f"{label}: code + PKCE yields validated access and ID tokens for the signed-in subject")
        out.refused(oauth.redeem_code(http, client, code, verifier).status == 400, f"{label}: the code cannot be replayed")
        out.refused(oauth.introspect(http, ctx.service_client(op, app, f"rs-{label}", [READ])[0], t.access_token)
                    ["active"] is False, f"{label}: replaying a code ends the first redemption's session")
        code2, verifier2, _, _ = _code(http, client, user, password, ("openid", READ))
        out.refused(oauth.redeem_code(http, client, code2, oauth.pkce_pair()[0]).status == 400,
                    f"{label}: a wrong PKCE verifier is refused")
        out.refused(oauth.redeem_code(http, client, code2, verifier2, "http://127.0.0.1:9/other").status == 400,
                    f"{label}: a redirect URI differing from the request is refused")

    # Population separation on the login pages and on a live browser session.
    out.refused(_fails(lambda: _code(http, shop_web, person, person_pw, ("openid",))),
                "workforce credentials are refused on the customer login page")
    out.refused(_fails(lambda: _code(http, staff_web, customer.email, customer.password, ("openid",))),
                "customer credentials are refused on the workforce login page")
    _, _, _, customer_session = _code(http, shop_web, customer.email, customer.password, ("openid",))
    verifier, challenge = oauth.pkce_pair()
    reuse = http.get("/oauth/authorize?" + oauth.urlencode({
        "response_type": "code", "client_id": staff_web.client_id, "redirect_uri": staff_web.redirect_uri,
        "scope": "openid", "state": "s", "nonce": "n", "code_challenge": challenge, "code_challenge_method": "S256"}),
        session=customer_session, headers={"Accept": "text/html"})
    out.refused(reuse.status == 302 and reuse.headers.get("Location", "").endswith("/login"),
                "a signed-in customer's browser gets no workforce code: it is sent to the workforce login")
    unverified = ciam.provision(ctx, op, "pending")
    out.refused(_fails(lambda: _code(http, shop_web, unverified.email, unverified.password, ("openid",))),
                "an unverified customer cannot sign in")
    out.refused(_fails(lambda: _code(http, shop_web, customer.email, oauth.Secret("wrong-password-123", "pw"), ("openid",))),
                "a wrong customer password is refused")

    # Request-level denials (no code is issued).
    _, challenge = oauth.pkce_pair()
    base = {"response_type": "code", "client_id": staff_web.client_id, "scope": "openid", "state": "s", "nonce": "n"}
    no_pkce = http.get("/oauth/authorize?" + oauth.urlencode({**base, "redirect_uri": staff_web.redirect_uri}),
                       headers={"Accept": "text/html"})
    out.refused(no_pkce.status == 400, "an authorization request without S256 PKCE is refused")
    bad_redirect = http.get("/oauth/authorize?" + oauth.urlencode({**base, "redirect_uri": "http://127.0.0.1:9/evil",
                                                                  "code_challenge": challenge,
                                                                  "code_challenge_method": "S256"}),
                            headers={"Accept": "text/html"})
    out.refused(bad_redirect.status == 400 and "code=" not in bad_redirect.headers.get("Location", ""),
                "an unregistered redirect URI is refused without a redirect")
    http.delete(f"{ctx.admin_base()}/applications/{app['id']}/clients/{shop_record['id']}", bearer=op).expect(204)
    out.refused(_fails(lambda: _code(http, shop_web, customer.email, customer.password, ("openid",))),
                "a disabled client cannot start a sign-in")
    out.consumer_must += ["create verifier, state and nonce per login; verify state before redeeming and nonce on the ID token",
                          "use the client of the right population; never accept a customer token where a workforce one is required"]
    return out


if __name__ == "__main__":
    standalone(run)
