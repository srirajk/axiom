"""IDP-11 — provisioning workforce users and CIAM customers; groups, memberships and roles.

Standards and labels: SCIM 2.0 (RFC 7643/7644) for workforce users and groups; Axiom's own management API
(provider-specific setup adapter) for workforce users, application memberships/roles and CIAM customers. OIDC does not
standardize role creation; none is claimed.

1. Teaches: creating, reading, updating and disabling people and groups through supported APIs, assigning and removing
   an application role and observing the effect, and provisioning a customer without manufacturing verified state.
   Populations: workforce (users/groups/roles) and CIAM (customers), kept separate.
2. Setup: the tenant_admin provisioning operator; a SCIM provisioning source created by the operator (its bearer
   credential is returned once and held in memory only).
3. Records: SCIM users and a group, management-API users, an application with role and membership, two customers.
4. Calls: ``POST/GET/PATCH /scim/v2/Users``, ``POST/GET/PATCH /scim/v2/Groups`` (SCIM bearer);
   ``POST/GET/PUT/DELETE /users`` and ``…/applications/{a}/access/memberships/{m}/roles[/{r}]`` (operator bearer);
   ``POST /admin/tenants/{t}/ciam/customers`` and the customer's own verification challenge.
5. Tokens: the role assignment's effect is observed as the issuer's decision at token exchange (scope granted or refused).
6. Positive: SCIM user and group create/read/update with membership add/remove; management-API create/read/update/disable;
   role assignment then removal changes what the person may obtain; a provisioned customer is PENDING and unverified
   until the customer verifies. Denials: duplicate user and customer; a non-administrator cannot create users; SCIM
   without its bearer; a tenant administrator cannot administer another tenant; a disabled user cannot sign in;
   a pending customer cannot sign in.
7. Status: disable revokes the person's sessions at once (see IDP-08).
8. Cleanup: users disabled (soft delete), SCIM users deactivated, group membership removed, customers suspended,
   application/clients disabled. Axiom keeps disabled records for audit (residuals reported).
9. Consumer must: map its own directory to these APIs explicitly; never assume a customer is verified because it exists;
   keep workforce and customer identifiers in separate namespaces.
"""
from __future__ import annotations

from axiom_cookbook import ciam, oauth, topology
from axiom_cookbook.context import Context, strong_password
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.topology import READ

SCIM = "application/scim+json"


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-11 directory administration (workforce, groups, roles, customers)")
    http = ctx.http
    op = ctx.operator()

    # SCIM 2.0 source (operator creates it; credential returned once).
    source = http.post(f"{ctx.admin_base()}/scim-sources", bearer=op, json_body={"displayName": ctx.name("scim")}).expect(201).json()
    scim = Secret(source["bearerCredential"], "SCIM bearer")
    ctx.registry.add("scim source", source["id"], None, "credential revocation is two-person; source left for teardown")
    h = {"Content-Type": SCIM, "Accept": SCIM}
    user = http.request("POST", "/scim/v2/Users", bearer=scim, headers=h, json_body={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "externalId": ctx.name("ext-u1"),
        "userName": ctx.name("scim-u1"), "active": True, "emails": [{"value": ctx.name("scim-u1") + "@cookbook.invalid",
                                                                      "primary": True}]}).expect(201).json()
    def deactivate():
        current = http.request("GET", f"/scim/v2/Users/{user['id']}", bearer=scim, headers=h).json()
        return http.request("PATCH", f"/scim/v2/Users/{user['id']}", bearer=scim,
                            headers={**h, "If-Match": current["meta"]["version"]},
                            json_body={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                       "Operations": [{"op": "replace", "path": "active", "value": False}]})
    ctx.registry.add("scim user", user["id"], deactivate, "deactivate (SCIM PATCH active=false)")
    out.ok(http.request("GET", f"/scim/v2/Users/{user['id']}", bearer=scim, headers=h).expect(200).json()["userName"]
           == ctx.name("scim-u1"), "SCIM: a user is created and read back")
    group = http.request("POST", "/scim/v2/Groups", bearer=scim, headers=h, json_body={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "externalId": ctx.name("ext-g1"),
        "displayName": ctx.name("scim-g1"), "members": [{"value": user["id"]}]}).expect(201).json()
    out.ok([m["value"] for m in group["members"]] == [user["id"]], "SCIM: a group is created with the user as member")
    version = group.get("meta", {}).get("version")
    out.ok(bool(version), "SCIM resources carry a version (ETag) for optimistic concurrency")
    stale = http.request("PATCH", f"/scim/v2/Groups/{group['id']}", bearer=scim, headers={**h, "If-Match": 'W/"stale"'},
                         json_body={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                    "Operations": [{"op": "remove", "path": "members", "value": [{"value": user["id"]}]}]})
    out.refused(stale.status == 412, "SCIM: a PATCH with a stale If-Match is refused (412)")
    http.request("PATCH", f"/scim/v2/Groups/{group['id']}", bearer=scim, headers={**h, "If-Match": version}, json_body={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "remove", "path": "members", "value": [{"value": user["id"]}]}]}).expect(200, 204)
    out.ok(http.request("GET", f"/scim/v2/Groups/{group['id']}", bearer=scim, headers=h).expect(200).json().get("members") in ([], None),
           "SCIM: membership is removed")
    out.refused(http.request("GET", f"/scim/v2/Users/{user['id']}", headers=h).status == 401, "SCIM without its bearer is refused")
    dup = http.request("POST", "/scim/v2/Users", bearer=scim, headers=h, json_body={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "externalId": ctx.name("ext-u2"),
        "userName": ctx.name("scim-u1"), "active": True})
    out.refused(dup.status in (400, 409), "SCIM: a duplicate userName is refused")

    # Management API: users, roles, memberships.
    top = topology.build(ctx, op)
    person, pw = ctx.workforce_user(op, "dora")
    out.ok(http.get(f"/users/{person}", bearer=op).expect(200).json()["id"] == person, "management API: a user is created and read")
    http.put(f"/users/{person}", bearer=op, json_body={"email": f"{person}.new@cookbook.invalid"}).expect(200)
    out.ok(http.get(f"/users/{person}", bearer=op).expect(200).json()["email"].endswith(".new@cookbook.invalid"), "the user is updated")
    out.refused(http.post("/users", bearer=op, json_body={"id": person, "username": person, "email": "x@cookbook.invalid",
                                                          "password": strong_password().reveal(), "attributes": {}}).status == 409,
                "a duplicate user id is refused")
    member_token = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    out.refused(http.post("/users", bearer=member_token, json_body={"id": ctx.name("x"), "username": ctx.name("x"),
                                                                    "email": "y@cookbook.invalid", "password": "Aa1!aaaaaaaaaaaa",
                                                                    "attributes": {}}).status in (401, 403),
                "a non-administrator cannot create users")
    out.refused(http.get("/admin/tenants/some-other-tenant/applications", bearer=op).status in (403, 404),
                "a tenant administrator cannot administer another tenant")

    member = ctx.membership(op, top.portal_app, person, top.reader_role["id"])
    person_token = oauth.browser_login(http, top.web, person, pw, ("openid", READ)).access_token
    out.ok(oauth.exchange(http, top.portal_svc, person_token, top.portal_app["audience"], [READ]).status == 200,
           "with the reader role the person's token can be exchanged for orders.read")
    access = f"{ctx.admin_base()}/applications/{top.portal_app['id']}/access"
    http.delete(f"{access}/memberships/{member['id']}/roles/{top.reader_role['id']}", bearer=op).expect(200, 204)
    out.refused(oauth.exchange(http, top.portal_svc, person_token, top.portal_app["audience"], [READ]).status == 400,
                "after the role is removed the issuer refuses orders.read (checked live at exchange)")
    http.delete(f"/users/{person}", bearer=op).expect(204)
    try:
        oauth.browser_login(http, top.web, person, pw, ("openid",))
        disabled_refused = False
    except oauth.LoginFailed:
        disabled_refused = True
    out.refused(disabled_refused, "a disabled user cannot sign in")

    # CIAM customers: provisioned truthfully, verified only by the customer.
    pending = ciam.provision(ctx, op, "pia")
    out.ok(pending.record["status"] == "PENDING_VERIFICATION" and pending.record.get("emailVerifiedAt") is None
           and pending.record.get("provisioningSource") == "ADMINISTRATOR",
           "an administrator-provisioned customer is PENDING and unverified")
    out.refused(ciam.token(ctx, pending, top.web.client_id, [READ]).status in (400, 401), "a pending customer cannot sign in")
    code = ciam.request_verification(ctx, pending)
    verified = ciam.verify(ctx, code).expect(200).json()
    out.ok(verified["status"] == "ACTIVE" and verified.get("emailVerifiedAt"),
           f"the customer's own verification activates it ({ciam.SIMULATED_DELIVERY})")
    out.refused(http.post(f"{ctx.admin_base()}/ciam/customers", bearer=op, json_body={
        "email": pending.email, "displayName": "dup", "initialPassword": strong_password().reveal()}).status == 409,
                "a duplicate customer e-mail is refused")
    out.consumer_must += ["map your directory to SCIM or the management API explicitly; roles are provider-specific",
                          "never treat an existing customer as verified; read status and emailVerifiedAt"]
    return out


if __name__ == "__main__":
    standalone(run)
