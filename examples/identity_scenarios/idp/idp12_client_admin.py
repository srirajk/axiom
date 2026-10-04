"""IDP-12 — provisioning public and confidential OAuth clients: redirects, credentials, scopes, access and consent.

Labels: client registration and consent settings use Axiom's management API (a provider-specific setup adapter;
Dynamic Client Registration, RFC 7591, is not offered). The consent itself is the standard OAuth authorization consent
shown by the authorization server; its customer self-service listing/withdrawal is an Axiom API.

1. Teaches: creating each client posture and observing the effect of its settings. Populations: workforce and CIAM.
2. Setup: tenant_admin operator.
3. Records: application; a public browser client, a confidential web client, a secret service client, a
   ``private_key_jwt`` service client; a customer-facing client that requires consent; a member and a customer.
4. Calls: ``POST /admin/tenants/{t}/applications/{a}/clients`` with ``clientType`` (``PUBLIC_BROWSER``,
   ``CONFIDENTIAL_WEB``, ``CONFIDENTIAL_SERVICE``), ``population``, exact ``redirectUris``, ``scopes``,
   ``requireConsent``, ``accessTokenTtlSeconds``/``refreshTokenTtlSeconds``, ``tokenEndpointAuthMethod``, ``jwks``;
   ``GET …/clients``; ``…/access/memberships`` (assign/remove access); the consent page at ``/oauth/authorize``;
   ``GET``/``DELETE /ciam/tenants/{t}/customers/{c}/oauth-consents[/{clientId}]`` (customer self-service).
5. Tokens: a confidential client's secret is returned exactly once at creation; a public client has none; a key client
   registers only public keys.
6. Positive: each posture is created with the grants and authentication methods it should have; assigning access lets
   the person sign in, removing it stops new sign-ins; a consent-requiring client shows its consent page and issues only
   approved scopes; the customer sees and withdraws the consent and is asked again next time. Denials: an http
   (non-loopback) or fragment redirect; a secret for a public client; a private key in ``jwks``; a confidential web
   client without ``offline_access`` never gets refresh tokens; a person without access cannot sign in; declining
   consent yields ``access_denied``; operators cannot withdraw a customer's consent.
7. Status: removing access affects new sign-ins and exchanges; consent withdrawal ends the customer's sessions with
   that client at once.
8. Cleanup: clients/application disabled, user disabled, customer suspended.
9. Consumer must: store the one-time secret immediately in its secret store, register exact redirect URIs only, and
   present consent through the authorization server (never collect it in its own UI on the provider's behalf).
"""
from __future__ import annotations

from axiom_cookbook import ciam, keys as client_keys, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.topology import READ, WRITE


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-12 client administration and consent")
    http = ctx.http
    op = ctx.operator()
    app = ctx.application(op, "clients")
    clients_url = f"{ctx.admin_base()}/applications/{app['id']}/clients"
    spa, spa_rec = ctx.interactive_client(op, app, "c-spa", [READ])
    out.ok(spa.secret is None and spa_rec["tokenEndpointAuthMethods"] == ["none"] and spa_rec["grantTypes"] == ["authorization_code"],
           "public browser client: no secret, auth method none, authorization_code only")
    web, web_rec = ctx.interactive_client(op, app, "c-web", ["offline_access", READ], client_type="CONFIDENTIAL_WEB")
    out.ok(web.secret is not None and web_rec["tokenEndpointAuthMethods"] == ["client_secret_basic"]
           and set(web_rec["grantTypes"]) == {"authorization_code", "refresh_token"},
           "confidential web client: one-time secret, client_secret_basic, code + refresh")
    svc, svc_rec = ctx.service_client(op, app, "c-svc", [READ])
    out.ok(set(svc_rec["grantTypes"]) == {"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
           "service client: client_credentials and token exchange")
    key = client_keys.generate("ES256")
    _, key_created = ctx.key_client(op, app, "c-key", [READ], client_keys.jwks(key))
    out.ok(key_created["client"]["tokenEndpointAuthMethods"] == ["private_key_jwt"], "key client: private_key_jwt (ES256 key)")
    listed = {c["clientId"] for c in http.get(clients_url, bearer=op).expect(200).json()}
    out.ok({spa.client_id, web.client_id, svc.client_id} <= listed and "serviceSecret" not in str(http.get(clients_url, bearer=op).text),
           "listing clients never returns a secret")

    def create(body):
        return http.post(clients_url, bearer=op, json_body={"clientId": ctx.name("c-bad"), "postLogoutRedirectUris": [], **body})
    out.refused(create({"clientType": "PUBLIC_BROWSER", "redirectUris": ["http://app.example.com/cb"], "scopes": ["openid"]}).status == 400,
                "a plain-http, non-loopback redirect URI is refused")
    out.refused(create({"clientType": "PUBLIC_BROWSER", "redirectUris": ["https://app.example.com/cb#frag"], "scopes": ["openid"]}).status == 400,
                "a redirect URI with a fragment is refused")
    out.refused(create({"clientType": "PUBLIC_BROWSER", "redirectUris": ["https://app.example.com/cb"], "scopes": ["openid"],
                        "clientSecret": "a-secret-for-a-public-client-123456"}).status == 400, "a public client cannot have a secret")
    out.refused(create({"clientType": "CONFIDENTIAL_SERVICE", "scopes": [READ], "tokenEndpointAuthMethod": "private_key_jwt",
                        "jwks": {"keys": [{**key.public_jwk(), "d": "AAAA"}]}}).status == 400, "a private key in jwks is refused")
    out.refused(create({"clientType": "PUBLIC_BROWSER", "redirectUris": ["https://app.example.com/cb"],
                        "scopes": ["openid", "offline_access"]}).status == 400, "offline_access is not available to public clients")

    # Access assignment and removal.
    role = ctx.app_role(op, app, "reader", {READ: "allow"})
    person, pw = ctx.workforce_user(op, "ana")
    try:
        oauth.browser_login(http, spa, person, pw, ("openid",))
        no_access = False
    except oauth.LoginFailed:
        no_access = True
    out.refused(no_access, "a person without access to the application cannot sign in")
    membership = ctx.membership(op, app, person, role["id"])
    out.ok(oauth.browser_login(http, spa, person, pw, ("openid", READ)).access_token is not None, "assigning access enables sign-in")
    http.delete(f"{ctx.admin_base()}/applications/{app['id']}/access/memberships/{membership['id']}", bearer=op).expect(200, 204)
    try:
        oauth.browser_login(http, spa, person, pw, ("openid",))
        removed = False
    except oauth.LoginFailed:
        removed = True
    out.refused(removed, "removing access stops new sign-ins")

    # Consent: a customer-facing client that requires it.
    consent_web, _ = ctx.interactive_client(op, app, "c-consent", [READ, WRITE], population="CUSTOMER", require_consent=True)
    customer = ciam.verified(ctx, op, "cora")
    try:
        oauth.browser_login(http, consent_web, customer.email, customer.password, (READ,), approve=[])
        declined = False
    except oauth.ConsentRequired:
        declined = True
    out.refused(declined, "declining consent yields access_denied (no code)")
    t = oauth.browser_login(http, consent_web, customer.email, customer.password, ("openid", READ, WRITE), approve=[READ])
    granted = ctx.validator.access_token(t.access_token, app["audience"])
    out.ok(READ in str(granted["scope"]) and WRITE not in str(granted["scope"]), "only the approved scope is issued")
    self_service = ciam.access_token(ciam.token(ctx, customer, spa.client_id, [READ]))
    consents = http.get(f"{ciam.base(ctx)}/{customer.id}/oauth-consents", bearer=self_service).expect(200).json()
    out.ok(any(c["clientId"] == consent_web.client_id and READ in c["scopes"] for c in consents),
           "the customer sees the consent they gave")
    out.refused(http.delete(f"{ciam.base(ctx)}/{customer.id}/oauth-consents/{consent_web.client_id}", bearer=op).status in (401, 403),
                "an operator cannot withdraw the customer's consent")
    http.delete(f"{ciam.base(ctx)}/{customer.id}/oauth-consents/{consent_web.client_id}", bearer=self_service).expect(200)
    rs, _ = ctx.service_client(op, app, "c-rs", [READ])
    out.refused(oauth.introspect(http, rs, t.access_token)["active"] is False, "withdrawal ends the customer's session with that client")
    try:
        oauth.browser_login(http, consent_web, customer.email, customer.password, (READ,), approve=[])
        asked_again = False
    except oauth.ConsentRequired:
        asked_again = True
    out.ok(asked_again, "after withdrawal the consent page is shown again")
    out.consumer_must += ["store the one-time secret at once; register exact redirect URIs only",
                          "let the authorization server collect consent; do not imitate it in your UI"]
    return out


if __name__ == "__main__":
    standalone(run)
