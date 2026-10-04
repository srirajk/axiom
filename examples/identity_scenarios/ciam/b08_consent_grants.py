"""B08 — Customer consent (delegation grants): create, inspect, use, withdraw; customer approval versus admin setup.

1. Teaches: how a customer authorizes a workload to act for them, within a bounded client, purpose, audience, scope
   set and validity, and how withdrawal ends it. Population: CIAM customer + workload.
2. Setup: the operator registers the customer-facing client (B07), a workload application ``…-helper`` with a
   confidential client and workload record, a registered consent *purpose* for that workload, and a second,
   independent workload ``…-notify``.
3. Records: grants are ``/ciam/tenants/{t}/customers/{customerId}/delegation-grants/{grantId}``; the issued token
   carries the grant as ``delegation_id``.
4. Calls: administrative setup (operator token) — ``POST /admin/tenants/{t}/ciam/agent-workloads/{w}/purposes``,
   workload and client registration, and inspection ``GET /admin/tenants/{t}/ciam/delegation-grants``. Customer
   approval (customer token only: ``/ciam/**`` decodes nothing else) — ``POST …/delegation-grants``
   ``{agentWorkloadId, audience, scopes, purpose, purposeCode?, expiresAt}`` (``consentSource=CUSTOMER``),
   ``GET …/delegation-grants``, ``POST …/delegation-grants/{id}/revoke`` ``{reason}``;
   ``POST /oauth/token`` token-exchange with the customer token as ``subject_token`` and optional
   ``delegation_purpose`` (selects a purpose-bound grant; it grants nothing by itself).
5. Tokens: customer token (``sub``=customer, ``aud``=axiom-token-exchange) → delegated token (``sub``=customer,
   ``act``=the workload, ``client_id``=the workload's client, ``aud``=the grant's audience, ``delegation_id``).
6. Positive: customer-recorded consent with and without a registered purpose; operator inspection; exchange;
   introspection active. Denials: an operator recording or withdrawing consent (any kind); an ambiguous exchange matching two grants; another workload;
   scope widening; another customer's grant; another customer withdrawing; onward exchange of the delegated token;
   use after withdrawal and after expiry.
7. Status: withdrawal and expiry are checked live — a withdrawn grant's tokens introspect inactive at once and no new
   token is issued. An independent grant stays usable.
8. Cleanup: grants end with the customer's suspension (only the customer can withdraw one), purposes retired, workloads retired, clients/applications disabled, customers suspended.
9. Consumer must: show the customer what they are approving (the purpose, audience, scopes, expiry) in its own UI;
   check ``delegation_id`` status online for sensitive work; treat the delegated token as terminal (see the open
   decision on customer downstream continuation in the ledger).
"""
from __future__ import annotations

import time

from axiom_cookbook import ciam, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone

READ, WRITE = "orders.read", "orders.write"


def run(ctx: Context) -> Outcome:
    out = Outcome("B08 consent grants")
    op = ctx.operator()
    shop = ctx.application(op, "shop")
    web, _ = ctx.public_client(op, shop, "shop-web", [READ, WRITE])
    helper_app = ctx.application(op, "helper")
    helper, _ = ctx.service_client(op, helper_app, "helper-svc", [READ])
    helper_w = ctx.workload(op, helper, "helper")
    notify_app = ctx.application(op, "notify")
    notify, _ = ctx.service_client(op, notify_app, "notify-svc", [READ])
    notify_w = ctx.workload(op, notify, "notify")
    purpose_code = "order-status"
    ciam.purpose(ctx, op, helper_w["id"], purpose_code, [READ], 3600)
    dana, erin = ciam.verified(ctx, op, "dana"), ciam.verified(ctx, op, "erin")
    dana_token = ciam.access_token(ciam.token(ctx, dana, web.client_id, [READ, WRITE]))
    erin_token = ciam.access_token(ciam.token(ctx, erin, web.client_id, [READ]))
    helper_aud, notify_aud = helper_app["audience"], notify_app["audience"]

    # ------------------------------------------------------------------ customer approval vs administrative setup
    out.refused(ciam.grant(ctx, op, dana, helper_w["id"], helper_aud, [READ], purpose_code=purpose_code).status == 401,
                "an operator cannot record purpose-bound consent for the customer (the consent API accepts customer tokens only)")
    out.refused(ciam.grant(ctx, op, dana, helper_w["id"], helper_aud, [READ], "support setup").status == 401,
                "an operator cannot record plain consent for the customer either")
    by_customer = ciam.grant(ctx, dana_token, dana, helper_w["id"], helper_aud, [READ], "check my order status",
                             purpose_code=purpose_code).expect(201).json()
    plain = ciam.grant(ctx, dana_token, dana, helper_w["id"], helper_aud, [READ], "general help").expect(201).json()
    out.ok(by_customer["consentSource"] == "CUSTOMER" and by_customer["purposeCode"] == purpose_code,
           "consent recorded by the customer is marked CUSTOMER and bound to the registered purpose")
    out.ok(plain["consentSource"] == "CUSTOMER" and plain["purposeCode"] is None,
           "consent without a registered purpose keeps its free-text purpose and no purpose code")
    admin_view = {g["id"] for g in ctx.http.get(f"{ctx.admin_base()}/ciam/delegation-grants", bearer=op).expect(200).json()}
    out.ok({by_customer["id"], plain["id"]} <= admin_view, "the operator can inspect (not create) customer grants")
    listed = {g["id"] for g in ctx.http.get(f"{ciam.base(ctx)}/{dana.id}/delegation-grants",
                                            bearer=dana_token).expect(200).json()}
    out.ok({by_customer["id"], plain["id"]} <= listed, "the customer can inspect their grants")
    out.refused(ctx.http.get(f"{ciam.base(ctx)}/{dana.id}/delegation-grants", bearer=erin_token).status == 403,
                "another customer cannot inspect them")
    out.refused(ciam.grant(ctx, dana_token, dana, helper_w["id"], helper_aud, [WRITE]).status == 400,
                "consent cannot exceed the workload client's registered scopes")
    out.refused(ciam.grant(ctx, dana_token, dana, helper_w["id"], notify_aud, [READ]).status == 400,
                "consent names the workload's own audience, nothing else")

    # ------------------------------------------------------------------ exchange under consent
    out.refused(oauth.exchange(ctx.http, helper, dana_token, helper_aud, [READ]).status == 400,
                "an exchange that matches two grants is refused rather than silently choosing one")
    issued = oauth.exchange(ctx.http, helper, dana_token, helper_aud, [READ],
                            extra={"delegation_purpose": purpose_code}).expect(200)
    delegated = oauth.tokens(issued).access_token
    c = ctx.validator.access_token(delegated, helper_aud)
    out.facts["delegated_claims"] = {k: c.get(k) for k in ("sub", "client_id", "act", "delegation_id", "scope",
                                                            "token_use", "authority_profile", "identity_kind")}
    out.ok(c["sub"] == dana.id and c["act"]["client_id"] == helper.client_id and c["client_id"] == helper.client_id
           and c.get("delegation_id") == by_customer["id"] and c["scope"] in ([READ], READ),
           "the delegated token names the customer, the acting workload and the exact grant")
    out.ok(oauth.introspect(ctx.http, helper, delegated).get("active") is True, "introspection reports it active")
    out.refused(oauth.exchange(ctx.http, notify, dana_token, notify_aud, [READ]).status == 400,
                "a workload without a grant cannot act for the customer")
    out.refused(oauth.exchange(ctx.http, helper, dana_token, helper_aud, [WRITE],
                               extra={"delegation_purpose": purpose_code}).status == 400,
                "the exchange cannot widen scope beyond the grant")
    out.refused(oauth.exchange(ctx.http, helper, erin_token, helper_aud, [READ],
                               extra={"delegation_purpose": purpose_code}).status == 400,
                "one customer's grant does not authorize another customer's token")
    out.refused(oauth.exchange(ctx.http, helper, delegated, notify_aud, [READ]).status in (400, 401),
                "the delegated token is terminal: no onward exchange (customer continuation is an open decision)")

    # ------------------------------------------------------------------ independent grant, withdrawal, expiry
    independent = ciam.grant(ctx, dana_token, dana, notify_w["id"], notify_aud, [READ], "notifications").expect(201).json()
    out.refused(ciam.withdraw(ctx, erin_token, dana, by_customer["id"], "not mine").status == 403,
                "another customer cannot withdraw this consent")
    out.refused(ciam.withdraw(ctx, op, dana, by_customer["id"], "operator").status == 401,
                "an operator cannot withdraw it either (operators revoke the workload or suspend the customer)")
    ciam.withdraw(ctx, dana_token, dana, by_customer["id"], "customer withdrew").expect(200)
    out.refused(oauth.introspect(ctx.http, helper, delegated).get("active") is False,
                "after withdrawal the already-issued delegated token introspects inactive")
    out.refused(oauth.exchange(ctx.http, helper, dana_token, helper_aud, [READ],
                               extra={"delegation_purpose": purpose_code}).status == 400,
                "a withdrawn grant issues nothing")
    out.ok(oauth.exchange(ctx.http, notify, dana_token, notify_aud, [READ]).status == 200,
           "an independent grant to another workload is unaffected")
    ciam.withdraw(ctx, dana_token, dana, plain["id"], "no longer needed").expect(200)
    short = ciam.grant(ctx, dana_token, dana, helper_w["id"], helper_aud, [READ], "brief", seconds=4).expect(201).json()
    out.ok(oauth.exchange(ctx.http, helper, dana_token, helper_aud, [READ]).status == 200,
           "a short grant works while valid")
    time.sleep(5)
    out.refused(oauth.exchange(ctx.http, helper, dana_token, helper_aud, [READ]).status == 400,
                "an expired grant issues nothing")
    out.facts["grants"] = {"purpose_bound": by_customer["consentSource"], "plain": plain["consentSource"],
                           "independent": independent["id"][:8], "short_lived_s": 4, "short": short["id"][:8]}
    out.consumer_must += ["present purpose, audience, scope and expiry to the customer before recording consent",
                          "check delegation status online for sensitive work; the delegated token is terminal"]
    return out


if __name__ == "__main__":
    standalone(run)
