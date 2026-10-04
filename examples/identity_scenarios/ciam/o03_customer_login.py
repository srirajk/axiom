"""O03 — Customer sign-in: what Axiom supports today, and the open gap to a standard browser login.

1. Teaches: the customer sign-in contract and why it is *not yet* a standard OIDC browser login.
   Population: CIAM customer.
2. Setup: a customer-facing public client (B07) and one verified customer (B06).
3. Records: none beyond B06/B07 fixtures.
4. Calls: supported today — ``POST /ciam/tenants/{t}/customers/tokens`` with a JSON body
   ``{email, password, clientId, scopes}`` (credentials in the body, never in a URL) → 200
   ``{accessToken, tokenType, expiresIn, customerId, identityKind, clientId, scopes}``. Not supported for customers:
   ``/oauth/authorize`` + ``/login`` (that form authenticates workforce users only).
5. Tokens: one customer token (``aud=axiom-token-exchange``). There is no ID token, no refresh token and no OIDC
   session for customers; the token exists to be exchanged under consent (B08).
6. Positive: the supported endpoint issues a validated customer token. Denials: a customer's credentials on the
   workforce browser login; a wrong password; an unverified customer.
7. Status: the customer token is bound to ``token_version`` (suspension/recovery revoke it) and to its client.
8. Cleanup: fixtures as in B06/B07.
9. Consumer must: not treat this endpoint as an OIDC login. A customer-facing web application that needs standard
   authorization-code + PKCE customer login is blocked on the open decision recorded in the ledger (``D-O03``):
   which endpoint/login page authenticates customers, how the population is selected without confusion with
   workforce users, and what ID token/session contract customers receive. Axiom has not chosen that design.
"""
from __future__ import annotations

from axiom_cookbook import ciam, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret

READ = "orders.read"


def run(ctx: Context) -> Outcome:
    out = Outcome("O03 customer sign-in")
    op = ctx.operator()
    shop = ctx.application(op, "shop")
    web, _ = ctx.public_client(op, shop, "shop-web", [READ])
    fay = ciam.verified(ctx, op, "fay")

    r = ciam.token(ctx, fay, web.client_id, [READ]).expect(200)
    body = r.json()
    claims = ctx.validator.access_token(Secret(body["accessToken"], "customer token"), "axiom-token-exchange")
    out.ok(body["identityKind"] == "customer" and claims["sub"] == fay.id and "id_token" not in body
           and "refresh_token" not in body, "the supported customer endpoint issues one customer token, no ID token")
    out.ok(body["expiresIn"] > 0 and claims["exp"] - claims["iat"] == body["expiresIn"], "lifetime is stated")
    try:
        oauth.browser_login(ctx.http, web, fay.email, fay.password, ("openid", READ))
        browser = True
    except oauth.LoginFailed:
        browser = False
    out.refused(not browser, "a customer cannot use the workforce browser login (population separation)")
    wrong = ciam.Customer(fay.id, fay.email, Secret("wrong-password-123456", "password"), {})
    out.refused(ciam.token(ctx, wrong, web.client_id, [READ]).status in (400, 401), "a wrong password is refused")
    pending = ciam.provision(ctx, op, "pending")
    out.refused(ciam.token(ctx, pending, web.client_id, [READ]).status in (400, 401),
                "an unverified customer is refused")
    out.facts["open_decision"] = "D-O03 standard customer browser login (authorization code + PKCE) not designed"
    out.consumer_must += ["do not present the JSON customer token endpoint as an OIDC login",
                          "keep customer and workforce sign-in surfaces separate"]
    return out


if __name__ == "__main__":
    standalone(run)
