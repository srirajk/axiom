"""IDP-09 — client credential rotation, disable/retire, and issuer-audit read-back (signing-key rotation and restart
recovery: ``oauth/o08_key_and_credential_lifecycle.py`` and the opt-in ``tests/test_disruptive.py``).

1. Teaches: rotating a key-authenticated client's public keys with an overlap, disabling a client, retiring a
   workload, and reading the issuer's audit trail through Axiom's management API. Population: software clients.
2. Setup (setup adapter): two tenant administrators (two-person rule), an application, a ``private_key_jwt`` service
   client registered as a workload, a secret service client.
3. Records: application, clients, workload registration, identity-control requests (two-person, audited).
4. Calls: ``POST /admin/tenants/{t}/identity-control-requests`` (action ``REPLACE_APPLICATION_CLIENT_KEYS``, payload
   ``{"jwks": …public keys…}``) → ``/approve`` by a second operator → ``/apply``; ``DELETE …/clients/{id}`` (disable);
   ``POST …/agent-workloads/{w}/retire``; ``GET /admin/audit`` (Axiom-specific audit API, tenant-scoped).
5. Credentials: old key → old+new keys (overlap: both authenticate) → new key only (old refused). No private key or
   secret is ever sent to Axiom or appears in the audit trail.
6. Positive: overlap works, the new key works, audit read-back shows the rotation and disable actions. Denials: the
   proposer cannot approve; the old key is refused after the overlap ends; a disabled client gets no token and its
   outstanding token is inactive; a retired workload's client gets no token.
7. Status: client disable takes effect on introspection at once (no fabricated session for software tokens).
8. Cleanup: clients/application disabled, workload retired (terminal).
9. Consumer must: keep two keys during rotation windows, publish the new key before switching, remove the old one
   afterwards, and treat the audit API as a deployment contract (not a portable OAuth interface).
"""
from __future__ import annotations

import re

from axiom_cookbook import keys as client_keys, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.topology import READ

TOKEN_SHAPED = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")


def _two_person(ctx, op, record, payload):
    base = f"{ctx.admin_base()}/identity-control-requests"
    proposed = ctx.http.post(base, bearer=op, json_body={
        "action": "REPLACE_APPLICATION_CLIENT_KEYS", "targetType": "APPLICATION_CLIENT", "targetId": record["id"],
        "expectedTargetRevision": record["revision"], "payload": payload}).expect(201).json()
    url = f"{base}/{proposed['id']}"
    self_approval = ctx.http.post(url + "/approve", bearer=op, json_body={"expectedRevision": 1}).status
    second = ctx.second_operator()
    ctx.http.post(url + "/approve", bearer=second, json_body={"expectedRevision": 1}).expect(200)
    ctx.http.post(url + "/apply", bearer=second, json_body={"expectedRevision": 2}).expect(200)
    return self_approval


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-09 client credential lifecycle and audit")
    http = ctx.http
    op = ctx.operator()
    app = ctx.application(op, "keyed")
    rs, _ = ctx.service_client(op, app, "keyed-rs", [READ])
    endpoint = http.get("/.well-known/oauth-authorization-server").expect(200).json()["token_endpoint"]
    old, new = client_keys.generate("RS256"), client_keys.generate("RS256")
    client_id, created = ctx.key_client(op, app, "keyed-svc", [READ], client_keys.jwks(old))
    record = created["client"]
    workload = ctx.workload(op, oauth.Client(client_id), "keyed-svc")

    def token_with(key):
        return oauth.client_credentials_with_assertion(http, client_id,
                                                       oauth.client_assertion(client_id, key.private_key, key.kid, endpoint), [READ])

    out.ok(token_with(old).status == 200, "the registered key authenticates the client")
    self_approval = _two_person(ctx, op, record, {"jwks": client_keys.jwks(old, new)})
    out.refused(self_approval == 409, "the proposer cannot approve their own key replacement")
    out.ok(token_with(old).status == 200 and token_with(new).status == 200, "overlap: old and new keys both authenticate")
    current = next(c for c in http.get(f"{ctx.admin_base()}/applications/{app['id']}/clients", bearer=op).expect(200).json()
                   if c["clientId"] == client_id)
    _two_person(ctx, op, current, {"jwks": client_keys.jwks(new)})
    out.refused(token_with(old).status == 401, "after the overlap the old key is refused")
    issued = oauth.tokens(token_with(new).expect(200)).access_token
    out.ok(oauth.introspect(http, rs, issued)["active"] is True, "the new key's token is active")

    http.post(f"{ctx.admin_base()}/ciam/agent-workloads/{workload['id']}/retire", bearer=op,
              json_body={"reason": "IDP-09 retire"}).expect(200)
    out.refused(token_with(new).status in (400, 401), "a retired workload's client gets no new token")
    out.refused(oauth.introspect(http, rs, issued)["active"] is False, "…and its outstanding token is inactive")
    secret_svc, secret_record = ctx.service_client(op, app, "keyed-secret", [READ])
    s_token = oauth.tokens(oauth.client_credentials(http, secret_svc, [READ]).expect(200)).access_token
    http.delete(f"{ctx.admin_base()}/applications/{app['id']}/clients/{secret_record['id']}", bearer=op).expect(204)
    out.refused(oauth.client_credentials(http, secret_svc, [READ]).status == 401, "a disabled client gets no token")
    out.refused(oauth.introspect(http, rs, s_token)["active"] is False, "a disabled client's outstanding token is inactive")

    audit = http.get("/admin/audit", bearer=op, params={"size": 200}).expect(200).json()
    entries = audit.get("content", audit if isinstance(audit, list) else [])
    actions = {e["action"] for e in entries if client_id in str(e) or secret_svc.client_id in str(e)
               or record["id"] in str(e) or secret_record["id"] in str(e)}
    out.ok({"REPLACE_APPLICATION_CLIENT_KEYS", "DISABLE_APPLICATION_CLIENT"} <= actions,
           "audit read-back shows the key replacement and the client disable")
    text = str(entries)
    out.refused(not TOKEN_SHAPED.search(text) and secret_svc.secret.reveal() not in text and not re.search(r"[\"']d[\"']\s*:", text),
                "the audit trail carries no token, secret or private key material")
    out.facts["audited_actions"] = sorted(actions)
    out.consumer_must += ["rotate keys with an overlap: add the new key, switch, then remove the old one",
                          "audit and lifecycle APIs are Axiom deployment contracts, not portable OAuth interfaces"]
    return out


if __name__ == "__main__":
    standalone(run)
