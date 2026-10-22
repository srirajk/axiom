"""B12 — registering a custom OAuth business scope for one tenant through the API (no Helm change, no restart).

1. Teaches: how a tenant administrator approves a custom scope name, and that approval is vocabulary only: the name
   becomes usable in this tenant's client registrations and token requests, but grants nobody any authority.
   Population: software client (the same name can then be used by workforce/customer clients and exchange edges).
2. Setup: the tenant_admin provisioning operator (Axiom management API; provider-specific setup adapter).
3. Records: one catalog entry (the scope name; there is no delete API, so it remains as a residual), one application
   and one confidential service client (disabled at cleanup).
4. Calls: ``POST /admin/tenants/{t}/business-scopes`` ``{"scope", "description"}`` → 201 (200 for an identical repeat);
   ``GET /admin/tenants/{t}/business-scopes`` → ``{"configured": [deployment list], "registered": [this tenant]}``;
   ``POST …/applications/{a}/clients`` with the new scope; ``POST /oauth/token`` ``grant_type=client_credentials``.
5. Tokens: a client-credentials access token whose ``scope`` is the new name; nothing else changes.
6. Positive: register, list, repeat (idempotent), register a client for it and obtain a token with it. Denials: invalid
   and reserved names (400), a different description for an existing name (409), a client registration with an
   unregistered name (400), a token request beyond the client's registration (``invalid_scope``), another tenant's path.
7. Status: the catalog is read live; a new name is usable at once. Names cannot be deactivated through the API yet.
8. Cleanup: the client and application are disabled; the scope name remains in the tenant catalog (reported).
9. Consumer must: treat a scope name as a label; enforce resource-level authorization at the receiver; register only
   names it needs, because they cannot yet be withdrawn.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone


def run(ctx: Context) -> Outcome:
    out = Outcome("B12 custom business scopes (tenant catalog API)")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    catalog = f"{ctx.admin_base()}/business-scopes"
    scope = f"{ctx.target.namespace}:invoke"
    before = http.get(catalog, bearer=op).expect(200).json()
    out.ok(scope not in [s["scope"] for s in before["registered"]] and isinstance(before["configured"], list),
           "the catalog lists the deployment-configured baseline separately from the tenant's registered names")
    created = http.post(catalog, bearer=op, json_body={"scope": scope, "description": "cookbook call"}).expect(201).json()
    ctx.registry.add("business scope", scope, None, "no delete/disable API: the name stays in the tenant catalog")
    out.ok(created["scope"] == scope and created["tenantId"] == ctx.tenant, "a tenant administrator registers the name")
    again = http.post(catalog, bearer=op, json_body={"scope": scope, "description": "cookbook call"}).expect(200).json()
    out.ok(again["id"] == created["id"], "an identical repeat is idempotent (200, same entry)")
    out.ok(scope in [s["scope"] for s in http.get(catalog, bearer=op).expect(200).json()["registered"]],
           "the name is listed for this tenant")
    out.refused(http.post(catalog, bearer=op, json_body={"scope": scope, "description": "other"}).status == 409,
                "the same name with a different description is a conflict (409)")
    for bad in ("NoSeparator", "Upper:Case", "axiom:anything", "urn:ietf:params:oauth", "openid:x"):
        out.refused(http.post(catalog, bearer=op, json_body={"scope": bad}).status == 400,
                    f"invalid or reserved name {bad!r} is refused (400)")
    out.refused(http.get("/admin/tenants/ckbk-not-this-tenant/business-scopes", bearer=op).status in (403, 404),
                "another tenant's catalog path is refused (the cross-tenant case with a real second tenant is in the Java IT)")

    app = ctx.application(op, "scoped")
    svc, record = ctx.service_client(op, app, "scoped-svc", [scope])
    out.ok(record["scopes"] == [scope], "a client is registered for the new name at once (no restart)")
    token = oauth.tokens(oauth.client_credentials(http, svc, [scope]).expect(200)).access_token
    claims = v.access_token(token, app["audience"])
    out.ok(scope in str(claims.get("scope")), "the client obtains a token carrying the new scope")
    wider = oauth.client_credentials(http, svc, [scope, f"{ctx.target.namespace}:other"])
    out.refused(wider.status == 400 and wider.oauth_error() == "invalid_scope",
                "a token request beyond the client's registration is refused (invalid_scope)")
    unregistered = http.post(f"{ctx.admin_base()}/applications/{app['id']}/clients", bearer=op, json_body={
        "clientId": ctx.name("unreg"), "clientType": "CONFIDENTIAL_SERVICE", "redirectUris": [],
        "postLogoutRedirectUris": [], "scopes": [f"{ctx.target.namespace}:never"]})
    out.refused(unregistered.status == 400, "a client registration with an unregistered name is refused")
    discovery = http.get("/.well-known/openid-configuration").expect(200).json()
    out.refused(scope not in discovery.get("scopes_supported", []),
                "discovery publishes only the deployment baseline, never a tenant's private catalog")
    out.consumer_must += ["a scope name is a label, not permission: authorize each request at the resource",
                          "register only names you need; the API cannot yet withdraw a name"]
    return out


if __name__ == "__main__":
    standalone(run)
