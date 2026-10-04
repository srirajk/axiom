"""B06 — Customer identities: administrator provisioning versus self-registration, and unverified versus verified.

1. Teaches: how a customer comes to exist and when it may sign in. Population: CIAM customer (never a workforce user).
2. Setup: the provisioning operator (``tenant_admin``) for administrator provisioning; self-registration is
   unauthenticated. A customer-facing public client (B07 explains it) to request a customer token.
3. Records: two customers in this run's namespace — ``…-ann`` (administrator-provisioned) and ``…-bob``
   (self-registered). ``customerId`` is the customer token's ``sub``.
4. Calls: ``POST /admin/tenants/{t}/ciam/customers`` ``{email, displayName, initialPassword}`` → 201
   ``{status: PENDING_VERIFICATION, emailVerifiedAt: null, provisioningSource: ADMINISTRATOR}`` (no code returned);
   ``POST /ciam/tenants/{t}/customers/registrations`` → 201 ``provisioningSource: SELF_REGISTRATION``;
   ``POST …/verification-challenges`` ``{email}`` → 202; ``POST …/verifications`` ``{token}`` → 200 ``ACTIVE``;
   ``POST …/tokens`` → 200; ``GET …/customers/{id}``; ``POST /admin/…/ciam/customers/{id}/suspend|reactivate``.
5. Tokens: the customer token has ``identity_kind=customer``, ``aud=axiom-token-exchange``, a ``token_version`` and
   no ``roles``. Suspension bumps ``token_version``, so earlier tokens stop working.
6. Positive: both creation paths, verification, sign-in after verification. Denials: sign-in before verification;
   duplicate e-mail; a customer reading another customer; a customer token on workforce and admin APIs; a workforce
   operator signing in as a customer; administration of another tenant; a suspended customer's token and sign-in.
7. Status: verification is the only thing that sets ``emailVerifiedAt``; neither creation path does. Code delivery in
   this estate is simulated (``LOCAL_DEMO``): it proves the verification endpoint, not mailbox delivery.
8. Cleanup: no customer delete API exists; active customers are suspended, pending ones remain unable to sign in.
9. Consumer must: treat ``provisioningSource`` and ``emailVerifiedAt`` as distinct facts; do not infer a verified
   address from an administrator having created the account.
"""
from __future__ import annotations

from axiom_cookbook import ciam
from axiom_cookbook.context import Context, strong_password
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.tokens import unverified_claims

READ = "orders.read"


def run(ctx: Context) -> Outcome:
    out = Outcome("B06 customer identities")
    op = ctx.operator()
    shop = ctx.application(op, "shop")
    web, _ = ctx.public_client(op, shop, "shop-web", [READ])

    # ------------------------------------------------------------------ administrator provisioning
    ann = ciam.provision(ctx, op, "ann")
    out.ok(ann.record["status"] == "PENDING_VERIFICATION" and ann.record["emailVerifiedAt"] is None
           and ann.record["provisioningSource"] == "ADMINISTRATOR",
           "administrator provisioning creates an unverified, pending identity marked ADMINISTRATOR")
    out.ok(not any(k in ann.record for k in ("localDemoAction", "token", "code")),
           "no verification code is returned to the administrator")
    out.refused(ciam.token(ctx, ann, web.client_id, [READ]).status in (400, 401),
                "an unverified customer cannot sign in")
    code = ciam.request_verification(ctx, ann)
    out.ok(code is not None, "the customer requests a code (" + ciam.SIMULATED_DELIVERY + ")")
    ann.record = ciam.verify(ctx, code).expect(200).json()
    out.ok(ann.record["status"] == "ACTIVE" and ann.record["emailVerifiedAt"] is not None
           and ann.record["provisioningSource"] == "ADMINISTRATOR",
           "verification activates the customer and records emailVerifiedAt; the source stays ADMINISTRATOR")
    out.refused(ciam.verify(ctx, code).status in (400, 404, 409), "a verification code works once")

    # ------------------------------------------------------------------ self-registration
    bob, delivery = ciam.register(ctx, "bob")
    out.ok(bob.record["provisioningSource"] == "SELF_REGISTRATION" and bob.record["emailVerifiedAt"] is None,
           "self-registration is marked SELF_REGISTRATION and starts unverified")
    out.facts["code_delivery"] = delivery
    out.refused(ctx.http.post(ciam.base(ctx) + "/registrations", json_body={
        "email": bob.email, "displayName": "dup", "password": strong_password().reveal()}).status == 409,
        "a second identity with the same e-mail is refused")
    out.refused(ctx.http.post(f"{ctx.admin_base()}/ciam/customers", bearer=op, json_body={
        "email": ann.email, "displayName": "dup", "initialPassword": strong_password().reveal()}).status == 409,
        "administrator provisioning of an existing e-mail is refused")
    ciam.verify(ctx, ciam.request_verification(ctx, bob)).expect(200)

    # ------------------------------------------------------------------ sign-in and population separation
    ann_token = ciam.access_token(ciam.token(ctx, ann, web.client_id, [READ]))
    claims = ctx.validator.access_token(ann_token, "axiom-token-exchange")
    out.ok(claims["sub"] == ann.id and claims["identity_kind"] == "customer" and "roles" not in claims,
           "the customer token names the customer, is marked customer and carries no roles")
    out.ok(ctx.http.get(f"{ciam.base(ctx)}/{ann.id}", bearer=ann_token).status == 200,
           "a customer can read their own identity")
    out.refused(ctx.http.get(f"{ciam.base(ctx)}/{bob.id}", bearer=ann_token).status in (401, 403),
                "a customer cannot read another customer")
    out.refused(ctx.http.get("/users", bearer=ann_token).status in (401, 403),
                "a customer token is not accepted by workforce APIs")
    out.refused(ctx.http.get(f"{ctx.admin_base()}/ciam/customers", bearer=ann_token).status in (401, 403),
                "a customer token is not accepted by administration APIs")
    out.refused(ctx.http.post(ciam.base(ctx) + "/tokens", json_body={
        "email": f"{ctx.operator_username}@cookbook.invalid", "password": ctx.operator_password.reveal(),
        "clientId": web.client_id, "scopes": [READ]}).status in (400, 401),
        "a workforce operator's credentials do not sign in as a customer")
    out.refused(ctx.http.post("/admin/tenants/some-other-tenant/ciam/customers", bearer=op, json_body={
        "email": "x@customers.cookbook.invalid", "displayName": "x",
        "initialPassword": strong_password().reveal()}).status in (403, 404),
        "a tenant_admin cannot provision customers in another tenant")

    # ------------------------------------------------------------------ suspension
    ctx.http.post(f"{ctx.admin_base()}/ciam/customers/{ann.id}/suspend", bearer=op).expect(200)
    out.refused(ctx.http.get(f"{ciam.base(ctx)}/{ann.id}", bearer=ann_token).status == 401,
                "suspension invalidates the customer's existing token immediately (token_version)")
    out.refused(ciam.token(ctx, ann, web.client_id, [READ]).status in (400, 401),
                "a suspended customer cannot sign in")
    ctx.http.post(f"{ctx.admin_base()}/ciam/customers/{ann.id}/reactivate", bearer=op).expect(200)
    out.ok(ciam.token(ctx, ann, web.client_id, [READ]).status == 200, "reactivation restores sign-in")
    out.refused(ctx.http.get(f"{ciam.base(ctx)}/{ann.id}", bearer=ann_token).status == 401,
                "reactivation does not revive the token issued before suspension")
    out.facts["token_version_claim"] = unverified_claims(ann_token).get("token_version")
    out.consumer_must += ["distinguish provisioningSource from emailVerifiedAt",
                          "never treat a customer token as a workforce or administrator credential"]
    return out


if __name__ == "__main__":
    standalone(run)
