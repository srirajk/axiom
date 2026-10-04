"""IDP-06 — standard refresh tokens for continued access without a new browser login (RFC 6749 section 6,
OIDC Core section 11 ``offline_access``, RFC 9700 section 4.14 refresh-token protection).

1. Teaches: renewal for a server-side web client (BFF) of a workforce person or a customer, and the replay defences.
   Populations: workforce and CIAM. (Axiom's proprietary standing-grant renewal is a separate optional extension.)
2. Setup (setup adapter): ``CONFIDENTIAL_WEB`` clients (authorization code + PKCE + client secret, refresh grant) for each
   population, a second web client of the same application, and a public browser client (never gets refresh tokens).
3. Records: application, clients, member, customer.
4. Calls: code flow with ``scope=openid offline_access …`` and client authentication; ``POST /oauth/token``
   ``grant_type=refresh_token`` with HTTP Basic; RP-initiated logout; the customer consent-withdrawal API.
5. Tokens: refresh tokens are opaque and rotate on every use; each refresh returns a new access token (and ID token)
   for the same subject and session. The family's absolute lifetime is the refresh-token TTL counted from sign-in.
6. Positive: offline_access yields a refresh token; renewal works for the right client and rotates. Denials: no
   ``offline_access`` → no refresh token; public client → none; wrong client; an access token as renewal input; reuse of
   a spent refresh token withdraws the whole family (current refresh and access tokens stop); of five concurrent
   redemptions exactly one succeeds; logout, disable, customer consent withdrawal and expiry stop renewal.
7. Status: withdrawal is online — introspection reports the family's access tokens inactive at once.
8. Cleanup: clients/application disabled, user disabled, customer suspended.
9. Consumer must: store the newest refresh token atomically, serialize refreshes per session, never retry with an old
   one (it withdraws the family), keep refresh tokens server-side only, and handle ``invalid_grant`` by signing in again.
"""
from __future__ import annotations

import threading
import time

from axiom_cookbook import ciam, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.topology import READ

REFRESH_TTL_S = 60


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-06 refresh tokens (workforce and CIAM)")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    app = ctx.application(op, "bff")
    rs, _ = ctx.service_client(op, app, "bff-rs", [READ])
    web, record = ctx.interactive_client(op, app, "bff-web", ["offline_access", READ], client_type="CONFIDENTIAL_WEB")
    other, _ = ctx.interactive_client(op, app, "bff-web2", ["offline_access", READ], client_type="CONFIDENTIAL_WEB")
    short, _ = ctx.interactive_client(op, app, "bff-short", ["offline_access", READ], client_type="CONFIDENTIAL_WEB",
                                      refresh_ttl=REFRESH_TTL_S)
    shop, _ = ctx.interactive_client(op, app, "bff-shop", ["offline_access", READ], client_type="CONFIDENTIAL_WEB",
                                     population="CUSTOMER")
    spa, _ = ctx.interactive_client(op, app, "bff-spa", [READ])
    out.ok("refresh_token" in record["grantTypes"] and record["refreshTokenTtlSeconds"], "the web client is registered for refresh")
    role = ctx.app_role(op, app, "reader", {READ: "allow"})
    person, pw = ctx.workforce_user(op, "rui")
    ctx.membership(op, app, person, role["id"])
    customer = ciam.verified(ctx, op, "rosa")

    out.refused(oauth.browser_login(http, web, person, pw, ("openid", READ)).refresh_token is None,
                "without offline_access no refresh token is issued")
    out.refused(oauth.browser_login(http, spa, person, pw, ("openid", READ)).refresh_token is None,
                "a public browser client never receives a refresh token")

    t = oauth.browser_login(http, web, person, pw, ("openid", "offline_access", READ))
    r1 = t.refresh_token
    out.ok(r1 is not None, "offline_access yields a refresh token")
    out.refused(oauth.refresh(http, other, r1).oauth_error() == "invalid_grant", "another client cannot use the refresh token")
    out.refused(oauth.refresh(http, web, t.access_token).oauth_error() == "invalid_grant", "an access token is not renewal input")
    n = oauth.tokens(oauth.refresh(http, web, r1).expect(200))
    out.ok(n.refresh_token is not None and n.refresh_token.reveal() != r1.reveal(), "renewal rotates the refresh token")
    out.ok(v.access_token(n.access_token, app["audience"])["sub"] == person and n.id_token is not None,
           "the renewed access and ID tokens are for the same person")
    out.refused(oauth.refresh(http, web, r1).oauth_error() == "invalid_grant", "a spent refresh token is refused")
    out.refused(oauth.refresh(http, web, n.refresh_token).oauth_error() == "invalid_grant",
                "reusing a spent token withdraws the family: the current refresh token stops too")
    out.refused(oauth.introspect(http, rs, n.access_token)["active"] is False,
                "…and the family's access token introspects inactive")

    # Concurrency: five simultaneous redemptions of one refresh token.
    c = oauth.browser_login(http, web, person, pw, ("openid", "offline_access", READ))
    statuses, barrier = [], threading.Barrier(5)
    def redeem():
        barrier.wait()
        statuses.append(oauth.refresh(http, web, c.refresh_token).status)
    threads = [threading.Thread(target=redeem) for _ in range(5)]
    [th.start() for th in threads]
    [th.join() for th in threads]
    out.ok(statuses.count(200) == 1, "of five concurrent redemptions exactly one succeeds")
    out.facts["concurrent_statuses"] = sorted(statuses)

    # Withdrawn authority: logout, disable, customer consent withdrawal.
    lo = oauth.browser_login(http, web, person, pw, ("openid", "offline_access", READ))
    out.ok(oauth.logout(http, lo.id_token).status in (200, 302), "RP-initiated logout is accepted")
    out.refused(oauth.refresh(http, web, lo.refresh_token).oauth_error() == "invalid_grant", "after logout renewal is refused")
    ct = oauth.browser_login(http, shop, customer.email, customer.password, ("openid", "offline_access", READ))
    cn = oauth.tokens(oauth.refresh(http, shop, ct.refresh_token).expect(200))
    out.ok(v.access_token(cn.access_token, app["audience"])["sub"] == customer.id, "a customer's web session renews too")
    self_service = ciam.access_token(ciam.token(ctx, customer, spa.client_id, [READ]))
    http.delete(f"{ciam.base(ctx)}/{customer.id}/oauth-consents/{shop.client_id}", bearer=self_service).expect(200)
    out.refused(oauth.refresh(http, shop, cn.refresh_token).oauth_error() == "invalid_grant",
                "after the customer withdraws the application's consent renewal is refused")
    out.refused(oauth.introspect(http, rs, cn.access_token)["active"] is False, "…and its access token is inactive")
    d = oauth.browser_login(http, web, person, pw, ("openid", "offline_access", READ))
    http.delete(f"/users/{person}", bearer=op).expect(204)
    out.refused(oauth.refresh(http, web, d.refresh_token).oauth_error() == "invalid_grant", "a disabled person cannot renew")

    # Expiry: the family ends at the refresh lifetime counted from sign-in (here 60 s).
    other_person, other_pw = ctx.workforce_user(op, "eve")
    ctx.membership(op, app, other_person, role["id"])
    e = oauth.browser_login(http, short, other_person, other_pw, ("openid", "offline_access", READ))
    time.sleep(REFRESH_TTL_S + 2)
    out.refused(oauth.refresh(http, short, e.refresh_token).oauth_error() == "invalid_grant", "an expired refresh token is refused")
    out.consumer_must += ["store the newest refresh token atomically and serialize renewals; never retry an old one",
                          "keep refresh tokens server-side (confidential web client); handle invalid_grant by signing in again"]
    return out


if __name__ == "__main__":
    standalone(run)
