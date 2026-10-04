"""B03 — Applications, a public browser client and a confidential service client.

1. Teaches: the three identifiers a consumer handles and must not confuse:
   * ``application.id`` — Axiom's internal record id (admin API paths only);
   * ``applicationKey`` / ``audience`` — the application's name and the ``aud`` its tokens carry;
   * ``client.clientId`` — the public OAuth ``client_id``; ``client.id`` is the internal record id.
   Population: none (client registration).
2. Setup: provisioning operator.
3. Records: one application, one PUBLIC_BROWSER client (exact redirect URI, PKCE required), one CONFIDENTIAL_SERVICE
   client whose secret Axiom generates and returns exactly once.
4. Calls: ``POST /admin/tenants/{t}/applications``, ``POST .../applications/{id}/clients``, ``GET .../clients``.
5. Tokens: none issued here (see O02, O04).
6. Positive: both clients registered with the expected grant types. Denials: the secret never appears again in reads;
   a public client cannot use client credentials; an insecure redirect URI is refused at registration
   (exact matching of the registered URI at login is shown in O02).
7. Expiry: n/a. 8. Cleanup: clients and application are disabled (``DELETE``), not erased.
9. Consumer must: store the confidential secret in its own secret store at creation time; it cannot be read back.
"""
from __future__ import annotations

from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone


def run(ctx: Context) -> Outcome:
    out = Outcome("B03 applications and clients")
    op = ctx.operator()
    app = ctx.application(op, "portal")
    public, public_record = ctx.public_client(op, app, "portal-web", ["reports.read"])
    service, service_record = ctx.service_client(op, app, "portal-svc", ["reports.read"])
    out.facts.update(application_id=app["id"], application_key=app["applicationKey"], audience=app["audience"],
                     public_client_id=public.client_id, public_client_record=public_record["id"])
    out.ok(app["id"] != app["applicationKey"] and public_record["id"] != public.client_id,
           "record ids, application keys and OAuth client ids are distinct identifiers")
    out.ok(public_record["pkceRequired"] is True and "authorization_code" in public_record["grantTypes"],
           "public browser client requires PKCE and uses authorization_code")
    out.ok("client_credentials" in service_record["grantTypes"], "confidential client may use client_credentials")
    listed = ctx.http.get(f"{ctx.admin_base()}/applications/{app['id']}/clients", bearer=op).expect(200)
    out.refused(service.secret.reveal() not in listed.text and "serviceSecret" not in listed.text,
                "the generated secret is never returned again")
    no_secret = ctx.http.post("/oauth/token", form={"grant_type": "client_credentials", "client_id": public.client_id,
                                                    "scope": "reports.read"})
    out.refused(no_secret.status in (400, 401), "a public client cannot obtain client-credentials tokens")
    insecure = ctx.http.post(f"{ctx.admin_base()}/applications/{app['id']}/clients", bearer=op, json_body={
        "clientId": ctx.name("insecure-web"), "clientType": "PUBLIC_BROWSER",
        "redirectUris": ["http://app.example.invalid/callback#frag"], "postLogoutRedirectUris": [], "scopes": ["openid"]})
    out.refused(insecure.status == 400, "a redirect URI that is plain http off loopback or has a fragment is refused")
    out.consumer_must.append("keep the one-time client secret in the consumer's own secret store")
    return out


if __name__ == "__main__":
    standalone(run)
