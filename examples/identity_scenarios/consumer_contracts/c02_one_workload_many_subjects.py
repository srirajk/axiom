"""C02 — One workload serving many people at once, in two tenants: no subject, grant, tenant or token mix-ups;
selective revocation.

Capability: IDP-10 (subject, client and tenant isolation under concurrency).

1. Teaches: a single workload client exchanging concurrently for different subjects gets tokens that each name the
   right subject and authority, and revoking one subject's authority leaves the others alone.
   Population: two workforce people and two CIAM customers in tenant A (one acting workload per population), plus a
   customer and a workload in a second tenant B, all exchanging concurrently.
2. Setup: the generic topology (workforce: ``portal-svc`` for two entitled people) plus a customer-facing client and a
   ``helper`` workload with one consent grant per customer. Tenant B is provisioned by the root platform administrator
   (``POST /admin/tenants``) with its own customer-facing client, ``helper-b`` workload, customer and grant.
3. Records: topology, a second entitled person, two verified customers, two grants.
4. Calls: ``POST /oauth/token`` token exchange, 60 calls on 8 threads interleaving subjects and tenants, plus 10
   concurrent cross-tenant attempts (each tenant's workload presenting the other tenant's customer token); then
   ``POST /admin/tenants/{t}/sessions/{sid}/revoke`` and a customer's grant withdrawal; ``/oauth/introspect``.
5. Tokens: each result's ``sub`` must equal the subject token's ``sub``; customer results carry the subject's own
   ``delegation_id``; workforce results carry ``act``=portal-svc.
6. Positive: every concurrent result matches its own subject, authority and tenant. Denials: every cross-tenant
   exchange; cross-tenant introspection (``active=false`` only); after revoking person A's session
   and customer A's grant, A's tokens are inactive and A's exchanges fail while B's continue.
7. Status: selective — only the revoked authority changes.
8. Cleanup: topology and CIAM fixtures as in O05/B08.
9. Consumer must: key caches, memory and results by subject *and* authority (``sub`` + ``delegation_id``/``sid``);
   never reuse one subject's token for another. Axiom clients are tenant-scoped, so "one workload client in two
   tenants" cannot exist; this contract shows concurrent work of workloads in two tenants and that nothing crosses.
"""
from __future__ import annotations

import datetime as dt
import secrets
from concurrent.futures import ThreadPoolExecutor

from axiom_cookbook import ciam, oauth, topology
from axiom_cookbook.context import Context, strong_password
from axiom_cookbook.oauth import Client
from axiom_cookbook.redaction import Secret
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.tokens import unverified_claims

READ = topology.READ


def run(ctx: Context) -> Outcome:
    out = Outcome("C02 one workload, many subjects")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http = ctx.http
    member_b, password_b = ctx.workforce_user(op, "member-b")
    ctx.membership(op, top.portal_app, member_b, top.reader_role["id"])
    person = {top.member: oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token,
              member_b: oauth.browser_login(http, top.web, member_b, password_b, ("openid", READ)).access_token}

    shop = ctx.application(op, "shop")
    web, _ = ctx.public_client(op, shop, "shop-web", [READ])
    helper_app = ctx.application(op, "helper")
    helper, _ = ctx.service_client(op, helper_app, "helper-svc", [READ])
    helper_w = ctx.workload(op, helper, "helper")
    customers, customer_tokens, grants = {}, {}, {}
    for suffix in ("cust-a", "cust-b"):
        c = ciam.verified(ctx, op, suffix)
        customers[c.id] = c
        customer_tokens[c.id] = ciam.access_token(ciam.token(ctx, c, web.client_id, [READ]))
        grants[c.id] = ciam.grant(ctx, customer_tokens[c.id], c, helper_w["id"], helper_app["audience"], [READ],
                                  "concurrency check").expect(201).json()["id"]

    # ------------------------------------------------------------------ tenant B (root platform administrator)
    root = ctx.root()
    tenant_b = "ckbk-" + secrets.token_hex(4)
    http.post("/admin/tenants", bearer=root, headers={"Idempotency-Key": "c02-" + tenant_b},
              json_body={"tenantId": tenant_b, "name": tenant_b, "slug": tenant_b}, timeout=180).expect(201, 202)
    admin_b = f"/admin/tenants/{tenant_b}"

    def b_app(suffix):
        app = http.post(admin_b + "/applications", bearer=root, json_body={
            "applicationKey": ctx.name(suffix), "displayName": suffix,
            "audience": f"https://{ctx.name(suffix)}.cookbook.invalid"}).expect(201).json()
        ctx.registry.add("tenant-B application", app["id"], lambda: http.delete(
            f"{admin_b}/applications/{app['id']}", bearer=ctx.root()), "disable")
        return app

    def b_client(app, suffix, client_type):
        body = {"clientId": ctx.name(suffix), "clientType": client_type, "postLogoutRedirectUris": [],
                "redirectUris": ["http://127.0.0.1:9/app/callback"] if client_type == "PUBLIC_BROWSER" else [],
                "scopes": (["openid"] if client_type == "PUBLIC_BROWSER" else []) + [READ]}
        made = http.post(f"{admin_b}/applications/{app['id']}/clients", bearer=root, json_body=body).expect(201).json()
        ctx.registry.add("tenant-B client", made["client"]["clientId"], lambda: http.delete(
            f"{admin_b}/applications/{app['id']}/clients/{made['client']['id']}", bearer=ctx.root()), "disable")
        return Client(made["client"]["clientId"], Secret(made["serviceSecret"], "tenant-B secret")
                      if made.get("serviceSecret") else None)

    shop_b, helper_app_b = b_app("shop-b"), b_app("helper-b")
    web_b = b_client(shop_b, "shop-b-web", "PUBLIC_BROWSER")
    helper_b = b_client(helper_app_b, "helper-b-svc", "CONFIDENTIAL_SERVICE")
    receiver_b = b_client(helper_app_b, "receiver-b", "CONFIDENTIAL_SERVICE")
    helper_w_b = http.post(admin_b + "/ciam/agent-workloads", bearer=root, json_body={
        "workloadRef": f"workload:{ctx.name('helper-b')}", "name": ctx.name("helper-b"),
        "oauthClientId": helper_b.client_id}).expect(201).json()
    ctx.registry.add("tenant-B workload", helper_w_b["id"], lambda: http.post(
        f"{admin_b}/ciam/agent-workloads/{helper_w_b['id']}/retire", bearer=ctx.root(),
        json_body={"reason": "cookbook cleanup"}), "retire (terminal)")
    email_b, password_b_cust = f"{ctx.name('cust-tb')}@customers.cookbook.invalid", strong_password()
    reg = http.post(f"/ciam/tenants/{tenant_b}/customers/registrations", json_body={
        "email": email_b, "displayName": "tenant-B customer", "password": password_b_cust.reveal()}).expect(201).json()
    cust_b_id = reg["customer"]["customerId"]
    ctx.registry.add("tenant-B customer", cust_b_id, lambda: http.post(
        f"{admin_b}/ciam/customers/{cust_b_id}/suspend", bearer=ctx.root()), "suspend")
    # Verification code returned to the customer's own request by the loopback-only local-demo aid
    # (ciam.SIMULATED_DELIVERY): it proves the endpoint, not mailbox delivery.
    http.post(f"/ciam/tenants/{tenant_b}/customers/verifications",
              json_body={"token": reg["localDemoAction"]["token"]}).expect(200)
    cust_b_token = Secret(http.post(f"/ciam/tenants/{tenant_b}/customers/tokens", json_body={
        "email": email_b, "password": password_b_cust.reveal(), "clientId": web_b.client_id,
        "scopes": [READ]}).expect(200).json()["accessToken"], "tenant-B customer token")
    grant_b = http.post(f"/ciam/tenants/{tenant_b}/customers/{cust_b_id}/delegation-grants", bearer=cust_b_token,
                        json_body={"agentWorkloadId": helper_w_b["id"], "audience": helper_app_b["audience"],
                                   "scopes": [READ], "purpose": "tenant B concurrency",
                                   "expiresAt": (dt.datetime.now(dt.timezone.utc)
                                                 + dt.timedelta(hours=1)).isoformat()}).expect(201).json()["id"]
    a_customer_any = next(iter(customers))

    jobs = ([("person", s) for s in person] * 10 + [("customer", s) for s in customers] * 10
            + [("tenant-b", cust_b_id)] * 20 + [("cross-a-to-b", cust_b_id)] * 5 + [("cross-b-to-a", a_customer_any)] * 5)

    def one(job):
        kind, subject = job
        if kind == "person":
            r = oauth.exchange(http, top.portal_svc, person[subject], top.portal_app["audience"], [READ])
        elif kind == "customer":
            r = oauth.exchange(http, helper, customer_tokens[subject], helper_app["audience"], [READ])
        elif kind == "tenant-b":
            r = oauth.exchange(http, helper_b, cust_b_token, helper_app_b["audience"], [READ])
        elif kind == "cross-a-to-b":   # tenant A's workload presents tenant B's customer token
            r = oauth.exchange(http, helper, cust_b_token, helper_app["audience"], [READ])
        else:                          # tenant B's workload presents tenant A's customer token
            r = oauth.exchange(http, helper_b, customer_tokens[subject], helper_app_b["audience"], [READ])
        claims = unverified_claims(oauth.tokens(r.expect(200)).access_token) if r.status == 200 else {}
        return kind, subject, r.status, claims

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, jobs))
    legit = [r for r in results if not r[0].startswith("cross")]
    crossed = [r for r in results if r[0].startswith("cross")]
    mixups = [(k, s[:8]) for k, s, status, c in legit
              if status != 200 or c.get("sub") != s
              or (k == "customer" and (c.get("delegation_id") != grants[s] or c.get("tenant_id") != ctx.tenant))
              or (k == "tenant-b" and (c.get("delegation_id") != grant_b or c.get("tenant_id") != tenant_b
                                       or (c.get("act") or {}).get("client_id") != helper_b.client_id))
              or (k == "person" and (c.get("act") or {}).get("client_id") != top.portal_svc.client_id)]
    out.ok(len(legit) == 60 and not mixups,
           "60 concurrent exchanges across two tenants: every token names its own subject, authority and tenant")
    out.refused(len(crossed) == 10 and all(status in (400, 401) for _, _, status, _ in crossed),
                "10 concurrent cross-tenant exchanges (each tenant's workload with the other's customer token) all fail")
    out.facts["concurrent_exchanges"] = {"total": len(results), "tenants": 2, "mixups": len(mixups),
                                         "cross_tenant_attempts": len(crossed),
                                         "cross_tenant_statuses": sorted({r[2] for r in crossed})}
    a_delegated = oauth.tokens(oauth.exchange(http, helper, customer_tokens[a_customer_any], helper_app["audience"],
                                              [READ]).expect(200)).access_token
    b_delegated = oauth.tokens(oauth.exchange(http, helper_b, cust_b_token, helper_app_b["audience"],
                                              [READ]).expect(200)).access_token
    out.refused(oauth.introspect(http, receiver_b, a_delegated) == {"active": False}
                and oauth.introspect(http, top.orders_receiver, b_delegated) == {"active": False},
                "each tenant's receiver learns only active=false about the other tenant's tokens")
    out.ok(oauth.introspect(http, receiver_b, b_delegated).get("active") is True,
           "tenant B's own receiver sees tenant B's token active")

    # ------------------------------------------------------------------ selective revocation
    a_person, a_customer = top.member, next(iter(customers))
    b_customer = [c for c in customers if c != a_customer][0]
    a_derived = oauth.tokens(oauth.exchange(http, top.portal_svc, person[a_person], top.portal_app["audience"],
                                            [READ]).expect(200)).access_token
    sid = unverified_claims(person[a_person])["sid"]
    sessions = http.get(f"{ctx.admin_base()}/sessions", bearer=op, params={"principalId": a_person,
                                                                          "status": "ACTIVE"}).expect(200).json()
    revision = next(s["revision"] for s in sessions["content"] if s["id"] == sid)
    http.post(f"{ctx.admin_base()}/sessions/{sid}/revoke", bearer=op, json_body={"expectedRevision": revision}).expect(200)
    ciam.withdraw(ctx, customer_tokens[a_customer], customers[a_customer], grants[a_customer], "selective").expect(200)
    out.refused(not oauth.introspect(http, top.orders_receiver, a_derived).get("active"),
                "person A's derived token is inactive after A's session is revoked")
    out.refused(oauth.exchange(http, top.portal_svc, person[a_person], top.portal_app["audience"], [READ]).status
                in (400, 401), "person A can no longer be exchanged for")
    out.refused(oauth.exchange(http, helper, customer_tokens[a_customer], helper_app["audience"], [READ]).status == 400,
                "customer A's withdrawn grant issues nothing")
    out.ok(oauth.exchange(http, top.portal_svc, person[member_b], top.portal_app["audience"], [READ]).status == 200,
           "person B is unaffected")
    out.ok(oauth.exchange(http, helper, customer_tokens[b_customer], helper_app["audience"], [READ]).status == 200,
           "customer B is unaffected")
    out.ok(oauth.exchange(http, helper_b, cust_b_token, helper_app_b["audience"], [READ]).status == 200,
           "the other tenant is unaffected by tenant A's revocations")
    out.facts["tenant_b_residual"] = "the second tenant itself is left for estate teardown (deprovisioning keeps audit)"
    out.consumer_must += ["key every cache and result by sub plus authority (sid / delegation_id)",
                          "never reuse one subject's token for another subject"]
    return out


if __name__ == "__main__":
    standalone(run)
