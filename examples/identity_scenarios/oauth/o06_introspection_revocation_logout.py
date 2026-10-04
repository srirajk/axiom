"""O06 — Status: introspection (RFC 7662), session revocation, OIDC RP-initiated logout and expiry.

1. Teaches: what "still valid" means for an Axiom token and how a receiver learns it. Population: workforce person and
   workload.
2. Setup: generic topology; a resource-side receiver client that introspects (HTTP Basic). A second tenant with its own
   client shows the disclosure boundary (created once by the root platform administrator).
3. Records: topology + one extra tenant (provisioned through ``POST /admin/tenants``; it is left for the estate
   teardown because tenant deprovisioning keeps audit evidence).
4. Calls: ``POST /oauth/introspect``; ``POST /connect/logout`` with form field ``id_token_hint`` (OIDC
   RP-Initiated Logout 1.0 — POST keeps the ID token out of URLs) in the person's browser session; ``POST /admin/tenants/{t}/sessions/{sid}/revoke``; ``POST /oauth/revoke`` (RFC 7009).
5. Tokens: a person's application token and the exchanged tokens derived from it; a workload's client-credentials
   token (no person, no session: its status is the client's and the workload's current state).
6. Positive: active with claims for the receiver of the same tenant. Denials/inactive: after logout, after
   administrative session revocation (derived exchange tokens too), after RFC 7009 revocation, after expiry, for an
   unauthenticated or wrong-secret caller, and for a client of another tenant (disclosure boundary).
7. Residual window (shown, not hidden): after logout the token still passes *offline* JWKS validation until its
   ``exp``; only an online status check (introspection, or a session-aware validator) sees the revocation.
8. Cleanup: topology records disabled.
9. Consumer must: decide per route whether offline validation is enough or whether to introspect; cache
   introspection results for no longer than its risk tolerance.
"""
from __future__ import annotations

import time
import uuid

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.oauth import Client
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import InvalidToken

READ = topology.READ


def _active(ctx: Context, caller: Client, token: Secret) -> bool:
    return bool(oauth.introspect(ctx.http, caller, token).get("active"))


def run(ctx: Context) -> Outcome:
    out = Outcome("O06 introspection, revocation, logout, expiry")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http, receiver = ctx.http, top.orders_receiver

    # Valid token: active, with claims, for a receiver of the same tenant.
    verifier, challenge = oauth.pkce_pair()
    code, browser = oauth.authorize_code(http, top.web, top.member, top.member_password, ("openid", READ), challenge,
                                         "state-1", "nonce-1")
    first = oauth.tokens(oauth.redeem_code(http, top.web, code, verifier).expect(200))
    second = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ))
    view = oauth.introspect(http, receiver, first.access_token)
    out.ok(view["active"] and view["sub"] == top.member and view["client_id"] == top.web.client_id,
           "a valid person token is active with its claims for a same-tenant receiver")
    derived = oauth.tokens(oauth.exchange(http, top.portal_svc, first.access_token, top.portal_app["audience"],
                                          [READ]).expect(200)).access_token
    out.ok(_active(ctx, receiver, derived), "a token derived by exchange is active while its subject session is")

    out.refused(http.post("/oauth/introspect", form={"token": first.access_token}).status == 401,
                "an unauthenticated introspection call is refused")
    wrong = Client(receiver.client_id, Secret("wrong-" + "x" * 30, "wrong secret"))
    out.refused(http.post("/oauth/introspect", basic=wrong.basic(), form={"token": first.access_token}).status == 401,
                "an introspection caller with a wrong secret is refused")

    # Disclosure boundary: a client of another tenant learns nothing.
    root = ctx.root()
    other_tenant = "ckbk-" + uuid.uuid4().hex[:8]
    # Regression (found by this cookbook): an Idempotency-Key equal to the tenant id used to deadlock provisioning on
    # its own lifecycle lock (same advisory-lock key). The key is deliberately the tenant id here.
    http.post("/admin/tenants", bearer=root, headers={"Idempotency-Key": other_tenant},
              json_body={"tenantId": other_tenant, "name": other_tenant, "slug": other_tenant},
              timeout=120).expect(201, 202)  # provisioning waits for the policy engine to load the tenant
    other_app = http.post(f"/admin/tenants/{other_tenant}/applications", bearer=root, json_body={
        "applicationKey": "foreign-rs", "displayName": "foreign", "audience": "https://foreign.cookbook.invalid"}).expect(201).json()
    created = http.post(f"/admin/tenants/{other_tenant}/applications/{other_app['id']}/clients", bearer=root, json_body={
        "clientId": ctx.name("foreign-rs"), "clientType": "CONFIDENTIAL_SERVICE", "redirectUris": [],
        "postLogoutRedirectUris": [], "scopes": [READ]}).expect(201).json()
    foreign = Client(created["client"]["clientId"], Secret(created["serviceSecret"], "foreign secret"))
    foreign_view = oauth.introspect(http, foreign, first.access_token)
    out.refused(foreign_view == {"active": False}, "a client of another tenant gets only active=false")

    # Logout in the person's browser session ends that authorization's durable session. OIDC RP-Initiated Logout 1.0
    # lets the OP accept POST; the cookbook uses a form POST so the ID token never appears in a URL, log or trace.
    logged_out = http.post("/connect/logout", session=browser, headers={"Accept": "text/html"},
                           form={"id_token_hint": first.id_token})
    out.ok(logged_out.status in (200, 302), "OIDC RP-initiated logout is accepted")
    out.refused(not _active(ctx, receiver, first.access_token), "after logout the token introspects inactive")
    out.refused(not _active(ctx, receiver, derived), "after logout tokens derived from it are inactive too")
    out.ok(_active(ctx, receiver, second.access_token), "an independent login of the same person is unaffected")
    offline_still_valid = True
    try:
        ctx.validator.access_token(first.access_token, top.portal_app["audience"])
    except InvalidToken:
        offline_still_valid = False
    out.ok(offline_still_valid, "residual window: offline JWKS validation still accepts the logged-out token until exp")
    out.facts["residual_window_seconds"] = int(view["exp"] - time.time())

    # Administrative revocation of a session.
    sessions = http.get(f"{ctx.admin_base()}/sessions", bearer=op, params={"principalId": top.member,
                                                                          "status": "ACTIVE"}).expect(200).json()
    target_session = next(s for s in sessions["content"] if s["clientId"] == top.web.client_id)
    http.post(f"{ctx.admin_base()}/sessions/{target_session['id']}/revoke", bearer=op,
              json_body={"expectedRevision": target_session["revision"]}).expect(200)
    out.refused(not _active(ctx, receiver, second.access_token), "after administrative revocation the token is inactive")

    # Workload token: RFC 7009 revocation and expiry (the cookbook profile issues 30-second workload tokens).
    w = oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200))
    out.ok(_active(ctx, receiver, w.access_token), "a workload token is active while client and workload are active")
    oauth.revoke(http, top.portal_svc, w.access_token).expect(200)
    out.refused(not _active(ctx, receiver, w.access_token), "after RFC 7009 revocation the workload token is inactive")
    expiring = oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200))
    out.facts["workload_token_expires_in"] = expiring.expires_in
    # Bounded wait: this profile issues 30-second workload tokens. A longer lifetime is a configuration error, so the
    # example fails at once instead of sleeping (it never waits more than 60 seconds).
    if not 0 < expiring.expires_in <= 60:
        raise AssertionError(f"workload token lifetime {expiring.expires_in}s is outside the cookbook profile (<= 60s)")
    time.sleep(expiring.expires_in + 2)
    out.refused(not _active(ctx, receiver, expiring.access_token), "an expired token is inactive")
    expired_offline = False
    try:
        ctx.validator.access_token(expiring.access_token, top.portal_app["audience"], leeway=0)
    except InvalidToken:
        expired_offline = True
    out.refused(expired_offline, "offline validation also refuses the expired token")
    out.consumer_must += ["introspect (or use a session-aware validator) where revocation must take effect before exp",
                          "treat introspection failure as inactive (fail closed)"]
    return out


if __name__ == "__main__":
    standalone(run)
