"""IDP-08 — revoking tokens and ending browser sessions through their distinct interfaces (RFC 7009, OIDC RP-Initiated
Logout 1.0).

1. Teaches: exactly what each action ends in Axiom. Populations: workforce (customers behave the same; see IDP-06).
2. Setup (setup adapter): an application with a workforce web client (refresh-capable), a public client, and a resource
   server client for status checks.
3. Records: application, clients, member.
4. Calls: ``POST /oauth/revoke`` (``token``, ``token_type_hint``; client-authenticated; the token must belong to the
   caller); ``POST /connect/logout`` (form ``id_token_hint``; ID token never in a URL); ``GET`` the revoked token's status
   via ``POST /oauth/introspect``.
5. Policy (Axiom's chosen, documented semantics):
   * revoking an access token ends that login's durable session: the access token, its exchanged descendants and its
     refresh family stop for online checks;
   * revoking a refresh token ends the refresh family and its current access token;
   * RP-initiated logout ends the login named by ``id_token_hint`` (session, refresh family, descendants) and the browser
     session; other logins of the same person continue;
   * none of these can recall a JWT already held: offline validation accepts it until ``exp`` (the residual window).
6. Positive: logout accepted; unrelated logins remain usable. Denials: revoked/logged-out tokens introspect inactive;
   refresh refused; exchange of a revoked subject refused; a client cannot revoke another client's token (the token stays
   active whatever status the request receives).
7. Status: online consumers see the change at once; offline consumers keep accepting until ``exp`` (measured below).
8. Cleanup: clients/application disabled, user disabled.
9. Consumer must: check online status where withdrawal must take effect before ``exp``; do not treat HTTP 200 from
   revocation as proof of an effect; handle 401/inactive by signing in again.
"""
from __future__ import annotations

import time

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.tokens import InvalidToken
from axiom_cookbook.topology import READ


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-08 revocation and logout")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    top = topology.build(ctx, op)
    web, _ = ctx.interactive_client(op, top.portal_app, "portal-bff", ["offline_access", READ],
                                    client_type="CONFIDENTIAL_WEB")
    rs = top.orders_receiver
    login = lambda client=web, scopes=("openid", "offline_access", READ): oauth.browser_login(  # noqa: E731
        http, client, top.member, top.member_password, scopes)

    # Access-token revocation ends the login: access, refresh family and descendants.
    a = login()
    child = oauth.tokens(oauth.exchange(http, top.portal_svc, a.access_token, top.portal_app["audience"], [READ]).expect(200))
    independent = login()
    out.ok(oauth.revoke(http, web, a.access_token).status == 200, "RFC 7009 revocation of an access token is accepted")
    out.refused(oauth.introspect(http, rs, a.access_token)["active"] is False, "the revoked access token is inactive")
    out.refused(oauth.introspect(http, rs, child.access_token)["active"] is False, "its exchanged descendant is inactive")
    out.refused(oauth.refresh(http, web, a.refresh_token).oauth_error() == "invalid_grant", "its refresh family is ended")
    out.ok(oauth.introspect(http, rs, independent.access_token)["active"] is True, "an independent login is unaffected")

    # Refresh-token revocation ends the family and its current access token.
    b = login()
    out.ok(oauth.revoke(http, web, b.refresh_token, "refresh_token").status == 200, "revocation of a refresh token is accepted")
    out.refused(oauth.refresh(http, web, b.refresh_token).oauth_error() == "invalid_grant", "the revoked refresh token is refused")
    out.refused(oauth.introspect(http, rs, b.access_token)["active"] is False, "the family's access token is inactive")

    # A client cannot revoke another client's token (RFC 7009 still answers 200).
    c = login()
    other_status = oauth.revoke(http, top.portal_svc, c.access_token).status
    out.refused(oauth.introspect(http, rs, c.access_token)["active"] is True,
                "another client's revocation request has no effect on the token")
    out.facts["foreign_revocation_status"] = other_status

    # RP-initiated logout ends the named login; offline validation still accepts until exp.
    d = login()
    e = login()
    out.ok(oauth.logout(http, d.id_token).status in (200, 302), "RP-initiated logout (form POST) is accepted")
    out.refused(oauth.introspect(http, rs, d.access_token)["active"] is False, "after logout the access token is inactive")
    out.refused(oauth.refresh(http, web, d.refresh_token).oauth_error() == "invalid_grant", "after logout renewal is refused")
    out.refused(oauth.exchange(http, top.portal_svc, d.access_token, top.portal_app["audience"], [READ]).status in (400, 401),
                "after logout the token cannot be exchanged")
    out.ok(oauth.introspect(http, rs, e.access_token)["active"] is True, "another login of the same person continues")
    try:
        claims = v.access_token(d.access_token, top.portal_app["audience"])
        out.ok(True, "residual window: offline validation still accepts the logged-out token until exp")
        out.facts["offline_residual_window_s"] = int(claims["exp"] - time.time())
    except InvalidToken:
        out.facts["offline_residual_window_s"] = 0
    out.consumer_must += ["use online status where withdrawal must take effect before exp",
                          "HTTP 200 from revocation is not proof; verify the affected authority"]
    return out


if __name__ == "__main__":
    standalone(run)
