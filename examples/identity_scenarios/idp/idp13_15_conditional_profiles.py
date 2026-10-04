"""IDP-13, IDP-14, IDP-15 — conditional profiles: what Axiom does and does not claim today.

None of the three profiles is selected for this baseline. This example proves the honest current state so a consumer
cannot mistake absence for support:

* IDP-13 sender-constrained tokens (RFC 9449 DPoP / RFC 8705 mTLS): **not selected**. Discovery advertises neither;
  a DPoP proof is ignored and the token is a plain bearer token. ``private_key_jwt`` (IDP-03) authenticates the
  client only and does not bind the token.
* IDP-14 external assertions (RFC 7523 JWT bearer grant, cross-domain chaining drafts): **not selected**. The grant is
  not advertised and is refused; Axiom's workload-federation client-assertion framework has no provider profile and
  refuses every assertion. Evidence is negative-only, which proves refusal, not support.
* IDP-15 assurance (OIDC ``acr``/``amr``/``auth_time``, RFC 9470): **partially available, profile not selected**.
  Interactive sign-ins carry ``acr=urn:openwolf:axiom:acr:pwd``, ``amr=["pwd"]`` and ``auth_time``; exchange preserves
  them unchanged; caller-supplied ``acr`` values never raise them. Not available: ``acr_values``/``max_age`` enforcement,
  step-up, MFA/passkeys (deferred by the owner).

1. Population: workforce (assurance), software (sender constraint, external assertion).
2. Setup: the generic exchange topology (IDP-05).
3. Records: as IDP-05.
4. Calls: discovery; ``POST /oauth/token`` with a ``DPoP`` header, with ``grant_type=…:jwt-bearer``, with the
   workload-federation assertion type; code flow and exchange for assurance claims.
5. Tokens: bearer access tokens only.
6. Positive: password-level assurance on interactive tokens and preserved through exchange. Denials: no DPoP binding;
   jwt-bearer and workload-federation assertions refused; caller-written ``acr`` ignored; workload and exchanged
   software tokens carry no human assurance.
7. Status: n/a.
8. Cleanup: as IDP-05.
9. Consumer must: enforce proof-of-possession itself if a route needs it; never accept foreign assertions on Axiom's
   behalf; require and check ``acr``/``auth_time`` per sensitive action and refuse when absent or stale.
"""
from __future__ import annotations

import secrets

from axiom_cookbook import keys as client_keys, oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import unverified_claims
from axiom_cookbook.topology import READ

PASSWORD_ACR = "urn:openwolf:axiom:acr:pwd"


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-13/14/15 conditional profiles (not selected / partial)")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    top = topology.build(ctx, op)
    meta = http.get("/.well-known/openid-configuration").expect(200).json()

    # IDP-13
    out.refused("dpop_signing_alg_values_supported" not in meta and not meta.get("tls_client_certificate_bound_access_tokens"),
                "IDP-13: no sender-constraint profile is advertised")
    with_dpop = http.post("/oauth/token", basic=top.portal_svc.basic(), headers={"DPoP": "not-a-proof"},
                          form={"grant_type": "client_credentials", "scope": READ})
    if with_dpop.status == 200:
        body = with_dpop.json()
        out.refused(body.get("token_type", "").lower() == "bearer" and "cnf" not in unverified_claims(oauth.tokens(with_dpop).access_token),
                    "IDP-13: a DPoP header is ignored; the token is an unbound bearer token")
    else:
        out.refused(True, "IDP-13: a DPoP header is not accepted as a binding")
    out.facts["IDP-13"] = "not selected: bearer tokens only; private_key_jwt authenticates the client, it does not bind tokens"

    # IDP-14
    key = client_keys.generate("RS256")
    foreign = oauth.client_assertion("https://partner.example", key.private_key, key.kid, meta["token_endpoint"])
    jwt_bearer = http.post("/oauth/token", basic=top.portal_svc.basic(), form={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": foreign})
    out.refused(jwt_bearer.status in (400, 401) and "access_token" not in jwt_bearer.text,
                "IDP-14: the RFC 7523 jwt-bearer grant is refused (not selected)")
    federated = http.post("/oauth/token", form={
        "grant_type": "client_credentials", "scope": READ, "client_id": top.portal_svc.client_id,
        "client_assertion_type": "urn:openwolf:params:oauth:client-assertion-type:workload-federation",
        "client_assertion": foreign, "client_assertion_profile": "any"})
    out.refused(federated.status == 401, "IDP-14: an external workload assertion is refused (no provider profile configured)")
    out.facts["IDP-14"] = "not selected: refusal only (negative evidence proves refusal, not support)"

    # IDP-15
    login = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ))
    c1 = v.access_token(login.access_token, top.portal_app["audience"])
    out.ok(c1.get("acr") == PASSWORD_ACR and c1.get("amr") == ["pwd"] and isinstance(c1.get("auth_time"), int),
           "IDP-15: an interactive sign-in carries acr (password level), amr=[pwd] and auth_time")
    hop = oauth.tokens(oauth.exchange(http, top.portal_svc, login.access_token, top.portal_app["audience"], [READ]).expect(200))
    c2 = v.access_token(hop.access_token, top.portal_app["audience"])
    out.ok(all(c2.get(k) == c1.get(k) for k in ("acr", "amr", "auth_time")),
           "IDP-15: exchange preserves acr, amr and auth_time unchanged")
    raised = oauth.exchange(http, top.portal_svc, login.access_token, top.portal_app["audience"], [READ],
                            {"acr_values": "urn:example:mfa", "acr": "urn:example:mfa"})
    raised_acr = unverified_claims(oauth.tokens(raised).access_token).get("acr") if raised.status == 200 else None
    out.refused(raised_acr in (None, PASSWORD_ACR), "IDP-15: caller-supplied acr values never raise the asserted assurance")
    sw = v.access_token(oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200)).access_token,
                        top.portal_app["audience"])
    out.refused("acr" not in sw and "auth_time" not in sw, "IDP-15: software tokens assert no human authentication")
    out.facts["IDP-15"] = "partial: password-level claims and propagation; acr_values/max_age enforcement, step-up, MFA not available"
    out.consumer_must += ["enforce proof-of-possession yourself if a route needs it (IDP-13 not selected)",
                          "check acr/auth_time per sensitive action; treat anything above password level as unavailable"]
    return out


if __name__ == "__main__":
    standalone(run)
