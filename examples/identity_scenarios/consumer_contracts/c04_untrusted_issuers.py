"""C04 — Untrusted issuers and unselected trust profiles are refused (negative-only evidence).

Capabilities: IDP-13 (sender constraint) and IDP-14 (external assertions), both conditional and not selected.
This contract proves *rejection only*. A negative-only test is not a working integration: each needs a selected
protocol/provider profile before positive support exists.

1. Teaches: which inbound trust Axiom accepts today (its own tokens; ``client_secret_basic``, registered-key ``private_key_jwt`` and public PKCE clients)
   and that everything else fails closed. Population: workload and external callers.
2. Setup: the generic topology; a locally generated RSA key standing in for a foreign issuer.
3. Records: topology only.
4. Calls: ``POST /oauth/token`` with (a) a subject token signed by a foreign key but claiming Axiom's issuer, (b) one
   claiming a partner issuer, (c) the RFC 7523 ``jwt-bearer`` grant, (d) a ``private_key_jwt`` assertion signed by a key the client never registered,
   (e) Axiom's workload-federation client assertion (no provider profile is configured), (f) non-access-token
   subject token types; ``GET /.well-known/oauth-authorization-server``.
5. Tokens: none issued.
6. Positive: discovery advertises only ``client_secret_basic``/``private_key_jwt``/``none`` and no DPoP/mTLS binding. Denials: (a)–(f).
7. Status: n/a.
8. Cleanup: topology. The foreign key exists only in memory.
9. Consumer must: not assume federation, sender-constrained tokens or partner assertions until a profile is selected
   and a positive contract exists; a receiver that needs proof-of-possession must enforce it itself today.
"""
from __future__ import annotations

import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import unverified_claims

READ = topology.READ
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
CLIENT_JWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
WORKLOAD_FEDERATION = "urn:openwolf:params:oauth:client-assertion-type:workload-federation"


def _foreign(claims: dict, key, kid: str = "foreign-kid") -> Secret:
    return Secret(jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid, "typ": "at+jwt"}), "foreign token")


def run(ctx: Context) -> Outcome:
    out = Outcome("C04 untrusted issuers (negative-only)")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http = ctx.http
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    real = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    copied = {**unverified_claims(real), "jti": str(uuid.uuid4())}
    now = int(time.time())

    forged_same_iss = _foreign(copied, key)
    out.refused(oauth.exchange(http, top.portal_svc, forged_same_iss, top.portal_app["audience"], [READ]).status
                in (400, 401), "a token claiming Axiom's issuer but signed by another key is refused")
    partner = _foreign({**copied, "iss": "https://partner.cookbook.invalid", "iat": now, "exp": now + 300}, key)
    out.refused(oauth.exchange(http, top.portal_svc, partner, top.portal_app["audience"], [READ]).status in (400, 401),
                "a partner-issued subject token is refused (no partner trust profile)")
    out.refused(http.post("/oauth/token", basic=top.portal_svc.basic(), form=[
        ("grant_type", JWT_BEARER), ("assertion", partner), ("scope", READ)]).oauth_error()
        in ("unsupported_grant_type", "invalid_grant", "unauthorized_client"),
        "the RFC 7523 jwt-bearer grant is not available")
    client_jwt = _foreign({"iss": top.portal_svc.client_id, "sub": top.portal_svc.client_id,
                           "aud": http.base_url + "/oauth/token", "iat": now, "exp": now + 60,
                           "jti": str(uuid.uuid4())}, key)
    out.refused(http.post("/oauth/token", form=[
        ("grant_type", "client_credentials"), ("client_id", top.portal_svc.client_id), ("scope", READ),
        ("client_assertion_type", CLIENT_JWT), ("client_assertion", client_jwt)]).status in (400, 401),
        "a private_key_jwt assertion signed by an unregistered (foreign) key is refused")
    out.refused(http.post("/oauth/token", form=[
        ("grant_type", "client_credentials"), ("client_id", top.portal_svc.client_id), ("scope", READ),
        ("client_assertion_type", WORKLOAD_FEDERATION), ("client_assertion", client_jwt),
        ("client_assertion_profile", "any")]).status == 401,
        "an external workload assertion is refused while no federation provider profile is configured")
    for token_type in ("urn:ietf:params:oauth:token-type:id_token", "urn:ietf:params:oauth:token-type:jwt",
                       "urn:ietf:params:oauth:token-type:saml2"):
        r = http.post("/oauth/token", basic=top.portal_svc.basic(), form=[
            ("grant_type", oauth.TOKEN_EXCHANGE), ("subject_token", real), ("subject_token_type", token_type),
            ("audience", top.portal_app["audience"]), ("scope", READ)])
        out.refused(r.status in (400, 401), f"subject_token_type {token_type.rsplit(':', 1)[-1]} is refused")
    meta = http.get("/.well-known/oauth-authorization-server").expect(200).json()
    methods = set(meta.get("token_endpoint_auth_methods_supported", []))
    out.ok(methods <= {"client_secret_basic", "private_key_jwt", "none"} and "dpop_signing_alg_values_supported" not in meta
           and not meta.get("tls_client_certificate_bound_access_tokens"),
           "discovery advertises only the supported client authentication and no sender-constrained tokens")
    out.facts["evidence_level"] = "negative-only; IDP-13/IDP-14 profiles not selected"
    out.consumer_must += ["enforce proof-of-possession yourself if a route needs it (Axiom issues bearer tokens)",
                          "do not accept partner or external-platform assertions on Axiom's behalf"]
    return out


if __name__ == "__main__":
    standalone(run)
