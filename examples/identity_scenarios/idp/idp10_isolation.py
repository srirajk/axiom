"""IDP-10 — subject, client, population and tenant isolation under concurrency and lifecycle changes.

1. Teaches: that one software client acting for many subjects never mixes them up, that workforce, customer and tenant
   boundaries hold, that revocation is selective, and that a disable cannot be outrun by a racing issuance.
   Populations: workforce, customer, software; two tenants.
2. Setup (setup adapter): the generic exchange topology (IDP-05) plus a customer-facing client in the same application;
   a second tenant (root administrator, ``POST /admin/tenants``) with its own application, workload and receiver.
3. Records: as IDP-05, plus the second tenant and its records (the tenant itself is a residual until estate teardown,
   because tenant deprovisioning keeps audit evidence).
4. Calls: concurrent ``POST /oauth/token`` exchanges and client-credentials requests; ``POST /oauth/introspect``;
   RP-initiated logout; client disable.
5. Tokens: identity in every check is the pair (``iss``, ``sub``), never ``sub`` or an e-mail alone.
6. Positive: 40 concurrent exchanges by one workload client for two people and two customers each name exactly their
   own subject and client; logging one person out stops only that person's tokens. Denials: a customer token is not a
   workforce/administrator credential; another tenant's client learns only ``active: false``; another tenant's workload
   cannot redeem this tenant's tokens; after a client disable returns, no token of that client is active and no new one
   is issued, however the requests race.
7. Status: every decision is taken from current state at the time of the call.
8. Cleanup: as IDP-05; tenant B records are disabled; tenant B remains until teardown.
9. Consumer must: key caches and results by (iss, sub) plus the authority it used; never reuse one subject's token
   for another; do not treat a customer token as a workforce or administrator token.
"""
from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor

from axiom_cookbook import ciam, oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.tokens import unverified_claims
from axiom_cookbook.topology import READ


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-10 isolation (subjects, populations, tenants, races)")
    http, v = ctx.http, ctx.validator
    op, root = ctx.operator(), ctx.root()
    top = topology.build(ctx, op)
    shop, _ = ctx.interactive_client(op, top.portal_app, "iso-shop", [READ], population="CUSTOMER")
    p2, p2_pw = ctx.workforce_user(op, "member2")
    ctx.membership(op, top.portal_app, p2, top.reader_role["id"])
    subjects = {}
    for user, pw in ((top.member, top.member_password), (p2, p2_pw)):
        subjects[user] = oauth.browser_login(http, top.web, user, pw, ("openid", READ))
    for name in ("cy", "cz"):
        c = ciam.verified(ctx, op, name)
        subjects[c.id] = oauth.browser_login(http, shop, c.email, c.password, ("openid", READ))

    def exchange(sub):
        r = oauth.exchange(http, top.portal_svc, subjects[sub].access_token, top.portal_app["audience"], [READ])
        claims = unverified_claims(oauth.tokens(r).access_token) if r.status == 200 else {}
        return sub, r.status, (claims.get("iss"), claims.get("sub")), claims.get("client_id")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(exchange, [s for s in subjects for _ in range(10)]))
    mixups = [r for r in results if r[1] != 200 or r[2] != (v.issuer, r[0]) or r[3] != top.portal_svc.client_id]
    out.ok(len(results) == 40 and not mixups,
           "40 concurrent exchanges by one workload client for four subjects: each token names its own (iss, sub)")
    out.facts["concurrent"] = {"total": len(results), "mixups": len(mixups)}

    a = next(iter(subjects))
    derived_a = oauth.tokens(oauth.exchange(http, top.portal_svc, subjects[a].access_token, top.portal_app["audience"],
                                            [READ]).expect(200)).access_token
    derived_b = oauth.tokens(oauth.exchange(http, top.portal_svc, subjects[p2].access_token, top.portal_app["audience"],
                                            [READ]).expect(200)).access_token
    oauth.logout(http, subjects[a].id_token)
    out.refused(oauth.introspect(http, top.orders_receiver, derived_a)["active"] is False, "logging A out stops A's derived token")
    out.ok(oauth.introspect(http, top.orders_receiver, derived_b)["active"] is True, "B's derived token is unaffected (selective)")

    customer_sub = [s for s in subjects if s not in (top.member, p2)][0]
    out.refused(http.get(f"{ctx.admin_base()}/applications", bearer=subjects[customer_sub].access_token).status in (401, 403),
                "a customer's application token is not accepted by the administration API")
    out.refused(http.get(f"{ciam.base(ctx)}/{customer_sub}", bearer=subjects[customer_sub].access_token).status == 401,
                "a customer's application token is not accepted by Axiom's own customer API (audience confusion)")

    # Tenant B.
    tenant_b = "ckbk-" + secrets.token_hex(4)
    http.post("/admin/tenants", bearer=root, headers={"Idempotency-Key": "idp10-" + tenant_b},
              json_body={"tenantId": tenant_b, "name": tenant_b, "slug": tenant_b}, timeout=180).expect(201, 202)
    admin_b = f"/admin/tenants/{tenant_b}"
    app_b = http.post(admin_b + "/applications", bearer=root, json_body={
        "applicationKey": ctx.name("b-app"), "displayName": "b", "audience": f"https://{ctx.name('b-app')}.cookbook.invalid"}
    ).expect(201).json()
    ctx.registry.add("tenant-B application", app_b["id"], lambda: http.delete(
        f"{admin_b}/applications/{app_b['id']}", bearer=ctx.root()), "disable")
    created = http.post(f"{admin_b}/applications/{app_b['id']}/clients", bearer=root, json_body={
        "clientId": ctx.name("b-svc"), "clientType": "CONFIDENTIAL_SERVICE", "redirectUris": [],
        "postLogoutRedirectUris": [], "scopes": [READ]}).expect(201).json()
    b_svc = oauth.Client(created["client"]["clientId"], oauth.Secret(created["serviceSecret"], "tenant-B secret"))
    http.post(f"{admin_b}/ciam/agent-workloads", bearer=root, json_body={
        "workloadRef": "workload:" + ctx.name("b-svc"), "name": ctx.name("b-svc"), "oauthClientId": b_svc.client_id}).expect(201)
    out.refused(oauth.introspect(http, b_svc, derived_b) == {"active": False}, "another tenant's client learns only active=false")
    out.refused(oauth.exchange(http, b_svc, subjects[customer_sub].access_token, app_b["audience"], [READ]).status == 400,
                "another tenant's workload cannot redeem this tenant's customer token")
    out.refused(oauth.exchange(http, b_svc, subjects[p2].access_token, app_b["audience"], [READ]).status == 400,
                "another tenant's workload cannot redeem this tenant's workforce token")
    out.facts["tenant_b_residual"] = "tenant B stays until estate teardown (deprovisioning keeps audit)"

    # Deactivation versus racing issuance.
    race_app = ctx.application(op, "race")
    racer, racer_record = ctx.service_client(op, race_app, "racer", [READ])
    def issue(_):
        r = oauth.client_credentials(http, racer, [READ])
        return oauth.tokens(r).access_token if r.status == 200 else None
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(issue, i) for i in range(16)]
        http.delete(f"{ctx.admin_base()}/applications/{race_app['id']}/clients/{racer_record['id']}", bearer=op).expect(204)
        issued = [f.result() for f in futures]
    out.refused(all(t is None or oauth.introspect(http, top.orders_receiver, t)["active"] is False for t in issued),
                "after the disable returns, no token of the disabled client is active, however the requests raced")
    out.refused(oauth.client_credentials(http, racer, [READ]).status == 401, "and no new token is issued")
    out.facts["race"] = {"requests": 16, "issued_before_disable": sum(t is not None for t in issued)}
    out.consumer_must += ["key every cache and result by (iss, sub) plus the authority used",
                          "never treat a customer token as a workforce or administrator token"]
    return out


if __name__ == "__main__":
    standalone(run)
