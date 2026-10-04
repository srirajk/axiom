"""B07 — Customer-facing application and client: what "application access" means for a customer.

1. Teaches: how a customer gets access to an application, and how that differs from workforce access.
   Population: CIAM customer.
2. Setup: the provisioning operator registers an application and a ``PUBLIC_BROWSER`` client whose ``scopes`` are the
   ceiling for customer tokens issued to it.
3. Records: application ``…-shop`` (audience ``https://…-shop.cookbook.invalid``), public client ``…-shop-web``
   (scopes ``orders.read``), a confidential client ``…-shop-svc``, one verified customer.
4. Calls: ``POST /admin/tenants/{t}/applications`` and ``…/clients``; ``POST /ciam/tenants/{t}/customers/tokens``
   ``{email, password, clientId, scopes}``; ``DELETE …/clients/{id}`` (disable).
5. Tokens: the customer token records ``client_id`` (the customer-facing client) and ``scope``; its audience is
   ``axiom-token-exchange`` — it is an *exchange subject*, not an access token for the application itself.
6. Positive: a customer token for the registered client and its scope. Denials: a scope the client does not carry,
   a scope that is not an approved business scope, a confidential client, a disabled client (issuance and the
   already-issued token), and an unknown client.
7. Status: disabling the client stops issuance and invalidates outstanding customer tokens for it.
8. Cleanup: clients and application disabled; customer suspended.
9. Consumer must: know that Axiom has **no customer roles, groups or memberships**. Customer access is "this client may
   ask for these scopes"; per-customer business entitlement (which orders are hers) is the resource's decision.
   Workforce application roles/memberships (B04) never apply to customers.
"""
from __future__ import annotations

from axiom_cookbook import ciam
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone

READ, WRITE = "orders.read", "orders.write"


def run(ctx: Context) -> Outcome:
    out = Outcome("B07 customer application access")
    op = ctx.operator()
    shop = ctx.application(op, "shop")
    web, web_record = ctx.public_client(op, shop, "shop-web", [READ])
    svc, _ = ctx.service_client(op, shop, "shop-svc", [READ])
    customer = ciam.verified(ctx, op, "carol")

    token = ciam.access_token(ciam.token(ctx, customer, web.client_id, [READ]))
    claims = ctx.validator.access_token(token, "axiom-token-exchange")
    out.ok(claims["client_id"] == web.client_id and claims["scope"] == READ,
           "the customer token is bound to the customer-facing client and its scope")
    out.refused(ciam.token(ctx, customer, web.client_id, [WRITE]).status == 400,
                "a scope the client does not carry is refused")
    out.refused(ciam.token(ctx, customer, web.client_id, ["admin.everything"]).status == 400,
                "a scope that is not an approved business scope is refused")
    out.refused(ciam.token(ctx, customer, svc.client_id, [READ]).status == 400,
                "customer sign-in through a confidential (service) client is refused")
    out.refused(ciam.token(ctx, customer, "no-such-client", [READ]).status == 400, "an unknown client is refused")

    ctx.http.delete(f"{ctx.admin_base()}/applications/{shop['id']}/clients/{web_record['id']}", bearer=op).expect(200, 204)
    out.refused(ciam.token(ctx, customer, web.client_id, [READ]).status == 400,
                "a disabled client cannot issue customer tokens")
    out.refused(ctx.http.get(f"{ciam.base(ctx)}/{customer.id}", bearer=token).status == 401,
                "a customer token issued through a now-disabled client is refused")
    out.facts["customer_access_model"] = "client scope ceiling; no customer roles/groups/memberships in Axiom"
    out.consumer_must += ["decide per-customer business entitlement at the resource",
                          "do not map workforce roles or memberships onto customers"]
    return out


if __name__ == "__main__":
    standalone(run)
