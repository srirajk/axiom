"""Unit tests for phase0_harness_h2 (H-2). Fully mocked: no real subprocess, socket, cluster or network access."""

from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import os
import secrets
import socket
import subprocess
import sys
import types
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

import phase0_harness as h1
import phase0_harness_h2 as h2
from test_phase0_harness import FakeCmd, PASSWORD, PORT, PREFIX, admin_claims, make_jwt

NOW = 1_800_000_000
PORT2 = PORT + 1
ISSUER_HOST = "axiom.axiom-phase0-test.svc.cluster.local"
HERE = os.path.dirname(os.path.abspath(__file__))
H1_SHA256 = {
    "phase0_harness.py": "10ffb18b65e09ffc66439583ae299ee0ac10a7aa724d398e4aedee342aa3eebc",
    "test_phase0_harness.py": "67e6fa72a9f5882710a2e5dcabf76b14b3d81a672a2a680277cacc38fa58f188",
}
V = h2.base_vars(PREFIX)


def events(out: io.StringIO) -> list[dict]:
    return [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]


def cases_of(evs: list[dict]) -> dict:
    return {e["case_id"]: e for e in evs if e["event"] == "h2_case"}


def summary_of(evs: list[dict]) -> dict:
    return [e for e in evs if e["event"] == "h2_summary"][-1]


def resp(status: int, obj=None, headers=()) -> tuple:
    body = b"" if obj is None else (obj if isinstance(obj, bytes) else json.dumps(obj).encode())
    return status, list(headers), body


# ---------------------------------------------------------------------------------------------------------------------
# Claims (shared by the fake server and evaluator tests)
# ---------------------------------------------------------------------------------------------------------------------

def p1_claims(v: dict, session_id: str, /, **over) -> dict:
    c = {"iss": h1.EXPECTED_ISSUER, "sub": v["user"], "aud": [v["bff_aud"]], "client_id": v["human_client"],
         "identity_kind": "workforce", "tenant_id": "meridian", "sid": session_id, "roles": [v["operator_role"]],
         "scope": ["openid", "profile", "quickstart:invoke"], "iat": NOW, "exp": NOW + 900}
    for k, val in over.items():
        if val is None:
            c.pop(k, None)
        else:
            c[k] = val
    return c


def hop_claims(hop: str, v: dict, prev_exp: int, hop_sid: str, /, **over) -> dict:
    now = NOW
    bff_act = {"sub": v["bff_wl_ref"], "client_id": v["bff_client"], "workload_id": v["bff_wl_id"]}
    agent_act = {"sub": v["agent_wl_ref"], "client_id": v["agent_client"], "workload_id": v["agent_wl_id"]}
    per = {
        "P2": dict(aud=[v["bff_aud"]], act=bff_act, client_id=v["bff_client"], azp=v["bff_client"],
                   authority_profile="workforce", token_use="exchange_subject",
                   authority_id=f"workforce:{v['bff_app_id']}:{v['user']}:{h2.EXPECTED_ENTITLEMENT_REVISION}"),
        "P3": dict(aud=[v["gateway_aud"]], act=bff_act, client_id=v["bff_client"], azp=v["bff_client"],
                   authority_profile="workload_continuation", token_use="gateway_authorization", authority_id=v["R1"]),
        "P4": dict(aud=[v["agent_aud"]], act=bff_act, client_id=v["broker_client"], azp=v["broker_client"],
                   authority_profile="gateway_backend", token_use="exchange_subject", authority_id=v["R2"]),
        "P5": dict(aud=[v["gateway_aud"]], act=agent_act, client_id=v["agent_client"], azp=v["agent_client"],
                   authority_profile="workload_continuation", token_use="gateway_authorization", authority_id=v["R3"]),
        "P6": dict(aud=[v["tool_aud"]], act=agent_act, client_id=v["broker_client"], azp=v["broker_client"],
                   authority_profile="gateway_backend", token_use="delegated_access", authority_id=v["R4"]),
    }[hop]
    c = {"iss": h1.EXPECTED_ISSUER, "tenant_id": "meridian", "sub": v["user"], "identity_kind": "workforce",
         "scope": ["quickstart:invoke"], "iat": now, "exp": min(prev_exp, now + 300), "sid": hop_sid,
         "subject_sid": v["p1_sid"], **per}
    for k, val in over.items():
        if val is None:
            c.pop(k, None)
        else:
            c[k] = val
    return c


# ---------------------------------------------------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------------------------------------------------

class SeqProc:
    def __init__(self, port):
        self.stdout = iter([f"Forwarding from 127.0.0.1:{port} -> 8084\n"])
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        if self.returncode is None:
            self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class SeqPopen:
    def __init__(self, ports=(PORT,)):
        self.ports = list(ports)
        self.calls = []
        self.procs = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        port = self.ports[min(len(self.procs), len(self.ports) - 1)]
        p = SeqProc(port)
        self.procs.append(p)
        return p


class FakeH2Server:
    """Admin APIs, browser login (302s, Set-Cookie, csrf HTML), token endpoint and sessions API."""

    def __init__(self, *, login_location="absolute", overrides=None, claim_overrides=None,
                 exchange_overrides=None, session_list_shape="page"):
        self.ports = {PORT, PORT2}
        self.login_location = login_location
        self.overrides = overrides or {}
        self.claim_overrides = claim_overrides or {}
        self.exchange_overrides = exchange_overrides or {}
        self.session_list_shape = session_list_shape
        self.allow_wrong_verifier = False
        self.allow_replay = False
        self.nomember_gets_code = False
        self.nomember_status = 403
        self.redeem_fail_on: set[int] = set()
        self.echo_code_on_replay = False
        self.tamper_state = False
        self.response_authority: dict = {}   # hop -> response authority_id override
        self.user_precheck_status = 404
        self.states_seen: list[str] = []
        self.pf_killer = None          # callable invoked on each exchange request
        self.calls: list[tuple[str, str]] = []
        self.requests: list[dict] = []
        self.bad_urls: list[str] = []
        self.admin_token = make_jwt(admin_claims(), {"alg": "RS256"})
        self.n = 0
        self.apps: dict = {}
        self.clients: dict = {}       # clientId -> {...}
        self.workloads: dict = {}     # oauthClientId -> id
        self.routes: list = []
        self.users: dict = {}
        self.memberships: dict = {}
        self.http_sessions: dict = {}
        self.codes: dict = {}
        self.redemptions = 0
        self.tokens: dict = {}        # token -> hop
        self.hop_claims: dict = {}
        self.iam_sessions: list = []
        self.revoked_sessions: list = []
        self.secrets_seen: list[str] = [PASSWORD, self.admin_token]

    # -- helpers --
    def _id(self, kind):
        self.n += 1
        return f"{kind}-{self.n:04d}"

    def _sensitive(self, value):
        self.secrets_seen.append(value)
        return value

    def vars(self) -> dict:
        v = dict(V)
        v["bff_app_id"] = next((aid for aid, doc in self.apps.items() if doc["applicationKey"] == f"{PREFIX}-bff"),
                               None)
        v["bff_wl_id"] = self.workloads.get(V["bff_client"])
        v["agent_wl_id"] = self.workloads.get(V["agent_client"])
        for i, rid in enumerate(self.routes):
            v[f"R{i + 1}"] = rid
        p1 = self.hop_claims.get("P1")
        v["p1_sid"] = p1["sid"] if p1 else None
        return v

    def _cookie_session(self, headers):
        cookies = {}
        for part in (headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, val = part.strip().split("=", 1)
                cookies[k] = val
        sid = cookies.get("JSESSIONID")
        if sid in self.http_sessions:
            return sid, self.http_sessions[sid], []
        sid = self._sensitive("JS" + secrets.token_urlsafe(32))
        self.http_sessions[sid] = {"user": None, "saved": None, "csrf": self._sensitive(secrets.token_urlsafe(32))}
        return sid, self.http_sessions[sid], [("Set-Cookie", f"JSESSIONID={sid}; Path=/; HttpOnly; SameSite=Lax")]

    def _loc(self, path):
        if self.login_location == "relative":
            return path
        if self.login_location == "issuer":
            return f"http://{ISSUER_HOST}:8084{path}"
        if self.login_location == "foreign":
            return "http://evil.example/phish"
        if self.login_location == "evil_login":
            return f"http://evil.example{path}"
        return f"http://127.0.0.1:{self.port}{path}"

    # -- dispatcher --
    def __call__(self, method, url, headers, body, timeout):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.port not in self.ports:
            self.bad_urls.append(url)
            raise AssertionError("request to a non-forwarded URL")
        self.port = parts.port
        path, query = parts.path, parts.query
        self.calls.append((method, path))
        self.requests.append({"method": method, "path": path, "query": query, "headers": dict(headers),
                              "body": body})
        key = (method, path)
        if key in self.overrides:
            r = self.overrides[key]
            out = r(headers, body) if callable(r) else r
            if out is not None:
                return out
        base = "/admin/tenants/meridian"
        if key == ("GET", "/.well-known/openid-configuration"):
            return resp(200, {"issuer": h1.EXPECTED_ISSUER})
        if key == ("GET", "/.well-known/oauth-authorization-server"):
            return resp(200, {"issuer": h1.EXPECTED_ISSUER, "grant_types_supported": [h1.TOKEN_EXCHANGE_GRANT]})
        if key == ("GET", "/actuator/health/readiness"):
            return resp(200, {"status": "UP"})
        if key == ("POST", "/auth/login"):
            if json.loads(body) != {"username": "admin", "password": PASSWORD}:
                return resp(401, {"error": "bad"})
            return resp(200, {"accessToken": self.admin_token})
        if path == "/oauth/authorize":
            return self.authorize(method, headers, query)
        if path == "/login":
            return self.login(method, headers, body)
        if key == ("POST", "/oauth/token"):
            return self.token(headers, body)
        assert headers.get("Authorization") == "Bearer " + self.admin_token, path
        return self.admin(method, path, query, body, base)

    # -- browser --
    def authorize(self, method, headers, query):
        assert method == "GET" and headers.get("Accept") == "text/html"
        q = dict(urllib.parse.parse_qsl(query))
        assert q["response_type"] == "code" and q["client_id"] == V["human_client"]
        assert q["redirect_uri"] == h2.REDIRECT_URI and q["scope"] == "openid profile quickstart:invoke"
        assert q["code_challenge_method"] == "S256" and q["code_challenge"] and q["state"] and q["nonce"]
        sid, sess, set_cookie = self._cookie_session(headers)
        if sess["user"] is None:
            sess["saved"] = query
            return resp(302, None, set_cookie + [("Location", self._loc("/login"))])
        if sess["user"] == V["nomember"] and not self.nomember_gets_code:
            return resp(self.nomember_status, b"<html>forbidden</html>", set_cookie)
        code = self._sensitive("code" + secrets.token_urlsafe(24))
        self.codes[code] = {"challenge": q["code_challenge"], "user": sess["user"], "used": False}
        self.states_seen.extend([q["state"], q["nonce"]])
        state = "tampered-state-value" if self.tamper_state else q["state"]
        return resp(302, None, set_cookie + [("Location", f"{h2.REDIRECT_URI}?code={code}&state={state}")])

    def login(self, method, headers, body):
        assert headers.get("Accept") == "text/html"
        sid, sess, set_cookie = self._cookie_session(headers)
        if method == "GET":
            csrf = sess["csrf"]
            page = (f'<html><form method="post" action="/login"><input value="{csrf}" type="hidden" '
                    f'name="_csrf"/><input id="username" name="username" type="text"></form>'
                    f"<form action='/logout'><input type='hidden' name='_csrf' value='{csrf}'></form></html>")
            return resp(200, page.encode(), set_cookie)
        assert headers.get("Content-Type") == "application/x-www-form-urlencoded"
        form = dict(urllib.parse.parse_qsl(body.decode()))
        assert set(form) == {"username", "password", "_csrf"}
        if form["_csrf"] != sess["csrf"] or self.users.get(form["username"]) != form["password"]:
            return resp(302, None, set_cookie + [("Location", self._loc("/login?error"))])
        saved = sess["saved"]
        del self.http_sessions[sid]
        new_sid = self._sensitive("JS" + secrets.token_urlsafe(32))
        self.http_sessions[new_sid] = {"user": form["username"], "saved": None,
                                       "csrf": self._sensitive(secrets.token_urlsafe(32))}
        return resp(302, None, [("Set-Cookie", f"JSESSIONID={new_sid}; Path=/; HttpOnly"),
                                ("Location", self._loc(f"/oauth/authorize?{saved}&continue"))])

    # -- token endpoint --
    def token(self, headers, body):
        form = dict(urllib.parse.parse_qsl(body.decode()))
        for k in ("code", "code_verifier", "subject_token"):
            if k in form:
                self._sensitive(form[k])
        if form["grant_type"] == "authorization_code":
            return self.redeem(headers, form)
        assert form["grant_type"] == h1.TOKEN_EXCHANGE_GRANT
        if self.pf_killer:
            self.pf_killer()
        return self.exchange(headers, form)

    def redeem(self, headers, form):
        assert "Authorization" not in headers
        assert form["client_id"] == V["human_client"] and form["redirect_uri"] == h2.REDIRECT_URI
        self.redemptions += 1
        if self.redemptions in self.redeem_fail_on:
            return resp(400, {"error": "invalid_request"})
        entry = self.codes.get(form["code"])
        if entry is None:
            return resp(400, {"error": "invalid_grant"})
        if entry["used"] and not self.allow_replay:
            body = {"error": "invalid_grant"}
            if self.echo_code_on_replay:
                body["error_description"] = f"code {form['code']} already used"
            return resp(400, body)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()) \
            .rstrip(b"=").decode()
        if challenge != entry["challenge"] and not self.allow_wrong_verifier:
            return resp(400, {"error": "invalid_grant"})
        entry["used"] = True
        sid = self._id("sid")
        self.iam_sessions.append({"id": self._id("sess"), "principalId": entry["user"], "status": "ACTIVE",
                                  "revision": 3})
        claims = p1_claims(self.vars(), sid, **self.claim_overrides.get("P1", {}))
        token = self._sensitive(make_jwt(claims))
        self.tokens[token] = "P1"
        self.hop_claims.setdefault("P1", claims)
        id_token = self._sensitive(make_jwt({"sub": entry["user"], "nonce": "n"}, {"alg": "RS256"}))
        return resp(200, {"access_token": token, "token_type": "Bearer", "id_token": id_token, "expires_in": 900})

    def exchange(self, headers, form):
        auth = headers["Authorization"]
        assert auth.startswith("Basic ")
        cid, secret = base64.b64decode(auth[6:]).decode().split(":", 1)
        cid, secret = urllib.parse.unquote_plus(cid), urllib.parse.unquote_plus(secret)
        client = self.clients.get(cid)
        if client is None or client.get("secret") != secret:
            return resp(401, {"error": "invalid_client"})
        assert form["subject_token_type"] == h1.ACCESS_TOKEN_TYPE == form["requested_token_type"]
        role = {V["bff_client"]: "bff", V["broker_client"]: "broker", V["agent_client"]: "agent",
                V["sibling_client"]: "sibling"}.get(cid)
        hop_in = self.tokens.get(form["subject_token"])
        aud, nscopes = form["audience"], len(form["scope"].split())
        v = self.vars()
        rules = [
            ("P2", role == "bff" and hop_in == "P1" and aud == v["bff_aud"] and nscopes == 1),
            ("N5", role == "sibling" and hop_in == "P2", "invalid_grant"),
            ("N6", role == "bff" and hop_in == "P2" and aud == v["agent_aud"], "invalid_target"),
            ("N7", role == "bff" and hop_in == "P2" and aud == v["gateway_aud"] and nscopes > 1, "invalid_scope"),
            ("P3", role == "bff" and hop_in == "P2" and aud == v["gateway_aud"]),
            ("N4", role == "broker" and hop_in == "P1", "invalid_grant"),
            ("N8", role == "agent" and hop_in == "P3", "invalid_grant"),
            ("P4", role == "broker" and hop_in == "P3" and aud == v["agent_aud"]),
            ("P5", role == "agent" and hop_in == "P4" and aud == v["gateway_aud"]),
            ("N9", role == "broker" and hop_in == "P5" and aud == v["bff_aud"], "invalid_target"),
            ("P6", role == "broker" and hop_in == "P5" and aud == v["tool_aud"]),
        ]
        for rule in rules:
            name, match = rule[0], rule[1]
            if not match:
                continue
            if name in self.exchange_overrides:
                status, obj = self.exchange_overrides[name]
                if isinstance(obj, dict) and isinstance(obj.get("access_token"), str):
                    self._sensitive(obj["access_token"])
                return resp(status, obj)
            if name.startswith("N"):
                return resp(400, {"error": rule[2], "error_description": "denied"})
            prev = self.hop_claims[hop_in]
            claims = hop_claims(name, v, prev["exp"], self._id("sid"), **self.claim_overrides.get(name, {}))
            token = self._sensitive(make_jwt(claims))
            self.tokens[token] = name
            self.hop_claims[name] = claims
            return resp(200, {"access_token": token, "issued_token_type": h1.ACCESS_TOKEN_TYPE,
                              "token_type": "Bearer", "expires_in": 300,
                              "authority_id": self.response_authority.get(name, claims.get("authority_id"))})
        return resp(400, {"error": "invalid_request", "error_description": "unexpected exchange"})

    # -- admin --
    def admin(self, method, path, query, body, base):
        doc = json.loads(body) if body else None
        if method == "GET" and path == f"{base}/applications":
            return resp(200, {"content": [{"applicationKey": "quickstart-agent"}]})
        if method == "POST" and path == f"{base}/applications":
            assert doc["displayName"] and doc["applicationKey"].startswith(PREFIX)
            aid = self._id("app")
            self.apps[aid] = doc
            return resp(201, {"id": aid})
        if method == "POST" and path.startswith(f"{base}/applications/") and path.endswith("/clients"):
            cid = doc["clientId"]
            entry = {"id": self._id("client"), "type": doc["clientType"]}
            out = {"client": {"id": entry["id"], "clientId": cid}}
            if doc["clientType"] == "CONFIDENTIAL_SERVICE":
                entry["secret"] = self._sensitive(f"svc-secret-{cid}-{secrets.token_hex(8)}")
                out["serviceSecret"] = entry["secret"]
            else:
                assert doc["redirectUris"] == [h2.REDIRECT_URI] and "openid" in doc["scopes"]
            self.clients[cid] = entry
            return resp(201, out)
        if method == "POST" and path == f"{base}/ciam/agent-workloads":
            assert doc["name"]
            wid = self._id("wl")
            self.workloads[doc["oauthClientId"]] = wid
            return resp(201, {"id": wid})
        if method == "POST" and path == f"{base}/agent-exchange/brokers":
            return resp(201, {"id": self._id("broker")})
        if method == "POST" and path == f"{base}/agent-exchange/routes":
            assert doc["expiresAt"].endswith("Z") and doc["purpose"] == h2.ROUTE_PURPOSE
            assert doc["destinationType"] in ("GATEWAY", "AGENT", "RESOURCE")
            if doc["destinationType"] == "AGENT":
                assert doc["destinationWorkloadId"] == self.workloads[V["agent_client"]]
            rid = self._id("route")
            self.routes.append(rid)
            return resp(201, {"id": rid})
        if method == "POST" and path.endswith("/access/roles"):
            assert doc["permissionEffects"] == {"quickstart:invoke": "allow"}
            return resp(201, {"id": self._id("role")})
        if method == "GET" and path.startswith("/users/"):
            if self.user_precheck_status == 404:
                return resp(404, {"error": "not_found"})
            return resp(self.user_precheck_status, {"id": path.split("/")[-1]})
        if method == "POST" and path == "/users":
            self.users[doc["id"]] = self._sensitive(doc["password"])
            return resp(201, {"id": doc["id"], "username": doc["username"]})
        if method == "POST" and path.endswith("/access/memberships"):
            mid = self._id("mem")
            self.memberships[mid] = doc
            return resp(201, {"id": mid})
        if method == "POST" and "/access/memberships/" in path and path.endswith("/roles"):
            return resp(200, {"id": path.split("/")[-2]})
        if method == "GET" and path == f"{base}/sessions":
            q = dict(urllib.parse.parse_qsl(query))
            assert q["status"] == "ACTIVE" and q["size"] == "100"
            items = [s for s in self.iam_sessions if s["principalId"] == q["principalId"] and s["status"] == "ACTIVE"]
            if self.session_list_shape == "list":
                return resp(200, items)
            return resp(200, {"content": items, "totalElements": len(items)})
        if method == "POST" and path.startswith(f"{base}/sessions/") and path.endswith("/revoke"):
            sid = path.split("/")[-2]
            s = next(s for s in self.iam_sessions if s["id"] == sid)
            if doc != {"expectedRevision": s["revision"]}:
                return resp(409, {"error": "conflict"})
            s["status"] = "REVOKED"
            self.revoked_sessions.append(sid)
            return resp(200, {"id": sid, "status": "REVOKED"})
        if path.endswith("/revoke") or method == "DELETE":
            return resp(204)
        raise AssertionError(f"unexpected {method} {path}")


def make_runner(server=None, *, popen=None, port_chooser=None, **kw):
    out = io.StringIO()
    server = server or FakeH2Server()
    popen = popen or SeqPopen()
    r = h2.H2Runner(run_cmd=FakeCmd(), popen=popen, http=server, out=out, now=lambda: NOW, prefix=PREFIX,
                    port_chooser=port_chooser or (lambda: PORT), pf_ready_timeout=2.0, **kw)
    return r, out, server


def run_full(server=None, **kw):
    r, out, server = make_runner(server, **kw)
    code = r.run()
    return code, events(out), out.getvalue(), server, r


def full_vars(**over) -> dict:
    v = dict(V, bff_app_id="app-bff", bff_wl_id="wl-bff", agent_wl_id="wl-agent", R1="route-1", R2="route-2",
             R3="route-3", R4="route-4", p1_sid="sid-p1")
    v.update(over)
    return v


# ---------------------------------------------------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------------------------------------------------

class H1UnchangedTests(unittest.TestCase):
    def test_h1_files_byte_identical(self):
        for name, digest in H1_SHA256.items():
            with open(os.path.join(HERE, name), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest, name)

    def test_h1_module_shared_and_still_works(self):
        self.assertIs(h2.h1, h1)
        self.assertIs(sys.modules["phase0_harness"], h1)
        self.assertEqual(h1.CASE_IDS, ("H1-P1", "H1-P2", "H1-N1", "H1-N2", "H1-N3"))
        self.assertTrue(issubclass(h2.H2Runner, h1.Runner))
        buf = io.StringIO()
        with mock.patch.object(subprocess, "run", side_effect=AssertionError), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError):
            self.assertEqual(h1.main([], out=buf), 0)
        self.assertTrue(any(json.loads(l)["event"] == "plan_case" for l in buf.getvalue().splitlines()))

    def test_h2_pins_h1_digest(self):
        self.assertEqual(h2.H1_SHA256, H1_SHA256["phase0_harness.py"])

    def test_loader_refuses_digest_mismatch(self):
        saved = sys.modules.pop("phase0_harness")
        try:
            with mock.patch.object(h2, "H1_SHA256", "0" * 64):
                with self.assertRaises(ImportError):
                    h2._load_h1()
                self.assertNotIn("phase0_harness", sys.modules)
        finally:
            sys.modules["phase0_harness"] = saved
        self.assertIs(h2._load_h1(), h1)

    def test_loader_refuses_foreign_module(self):
        fake = types.ModuleType("phase0_harness")
        fake.__file__ = "/tmp/elsewhere/phase0_harness.py"
        with mock.patch.dict(sys.modules, {"phase0_harness": fake}):
            with self.assertRaises(ImportError):
                h2._load_h1()
        self.assertIs(h2._load_h1(), h1)

    def test_loader_loads_sibling_by_path_when_not_imported(self):
        saved = sys.modules.pop("phase0_harness")
        try:
            mod = h2._load_h1()
            self.assertEqual(os.path.realpath(mod.__file__), os.path.realpath(os.path.join(HERE, "phase0_harness.py")))
        finally:
            sys.modules["phase0_harness"] = saved


class HelperTests(unittest.TestCase):
    def test_pkce_pair(self):
        verifier, challenge = h2.pkce_pair()
        self.assertTrue(43 <= len(verifier) <= 128)
        self.assertEqual(challenge, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                         .rstrip(b"=").decode())
        self.assertNotIn("=", challenge)
        v2, _ = h2.pkce_pair(lambda n: "x" * 200)
        self.assertEqual(v2, "x" * 96)

    def test_extract_csrf_attribute_order_and_quoting(self):
        self.assertEqual(h2.extract_csrf('<input type="hidden" name="_csrf" value="abc">'), "abc")
        self.assertEqual(h2.extract_csrf('<INPUT value="a&amp;b" name="_csrf" type="hidden"/>'), "a&b")
        self.assertEqual(h2.extract_csrf("<input name='_csrf'\n value='q1'>"), "q1")
        self.assertEqual(h2.extract_csrf(b'<input name="username"><input name="_csrf" value="t">'), "t")
        self.assertEqual(h2.extract_csrf('<input name="_csrf" value="first"><input name="_csrf" value="second">'),
                         "first")
        self.assertIsNone(h2.extract_csrf('<input name="other" value="x">'))
        self.assertIsNone(h2.extract_csrf('<input name="_csrf" value="">'))
        self.assertIsNone(h2.extract_csrf(None))

    def test_expectation_table_validation(self):
        h2.validate_expectations(h2.H2_EXPECTATIONS)
        self.assertEqual(len(h2.CASE_IDS), 15)
        bad = {"order": ["H2-P2", "H2-P1"], "cases": {k: h2.H2_EXPECTATIONS["cases"][k] for k in ("H2-P1", "H2-P2")}}
        with self.assertRaises(h1.HarnessError):
            h2.validate_expectations(bad)
        with self.assertRaises(h1.HarnessError):
            h2.validate_expectations({"order": ["H2-P1"], "cases": {}})

    def test_identities(self):
        n = h2.identity_names_h2(PREFIX)
        self.assertEqual(n["applications"]["tool"]["audience"], f"tool:meridian:{PREFIX}-tool")
        self.assertEqual(n["clients"]["broker"]["clientId"], f"{PREFIX}-gateway-broker")
        self.assertNotIn("tool", n["clients"])
        self.assertIn("tool", h2.identity_names_h2(PREFIX, True)["clients"])
        self.assertEqual(n["clients"]["human_web"]["clientType"], "PUBLIC_BROWSER")
        self.assertFalse(h2.TOOL_NEEDS_CLIENT)


class LocationGuardTests(unittest.TestCase):
    def test_local_targets(self):
        t = h2.classify_location("/login", PORT)
        self.assertEqual((t.kind, t.path, t.rewritten), ("local", "/login", False))
        t = h2.classify_location(f"http://127.0.0.1:{PORT}/oauth/authorize?a=1&continue", PORT)
        self.assertEqual((t.kind, t.path, t.rewritten), ("local", "/oauth/authorize?a=1&continue", False))

    def test_callback_extracted_never_local(self):
        t = h2.classify_location(f"{h2.REDIRECT_URI}?code=abc123&state=s1", PORT)
        self.assertEqual((t.kind, t.code, t.state, t.path), ("callback", "abc123", "s1", None))
        self.assertTrue(t.code_present)
        t = h2.classify_location(f"{h2.REDIRECT_URI}?error=access_denied&state=s1", PORT)
        self.assertEqual((t.kind, t.code, t.error), ("callback", None, "access_denied"))

    def test_rewrite_only_known_paths(self):
        t = h2.classify_location(f"http://{ISSUER_HOST}:8084/login", PORT)
        self.assertEqual((t.kind, t.path, t.rewritten, t.original_host), ("local", "/login", True, ISSUER_HOST))
        t = h2.classify_location(f"http://{ISSUER_HOST}:8084/oauth/authorize?x=y", PORT)
        self.assertEqual((t.path, t.rewritten), ("/oauth/authorize?x=y", True))
        for bad in (f"http://{ISSUER_HOST}:8084/oauth/token", f"http://{ISSUER_HOST}:8084/",
                    f"http://{ISSUER_HOST}:8084/login/../admin"):
            with self.assertRaises(h1.HarnessError, msg=bad):
                h2.classify_location(bad, PORT)

    def test_rejects_foreign_and_malformed(self):
        for bad in ("http://evil.example/login", "http://evil.example/oauth/authorize?x=1",
                    f"https://{ISSUER_HOST}:8084/login", f"http://{ISSUER_HOST}/login",
                    f"http://{ISSUER_HOST}:8085/login", f"http://127.0.0.2:{PORT}/login",
                    "http://evil.example/steal", "//evil.example/login", "javascript:alert(1)", "login",
                    f"http://user:pw@127.0.0.1:{PORT}/login", "http://127.0.0.1:9/other",
                    f"http://127.0.0.1:{PORT}/login#frag", "/../etc", "ftp://127.0.0.1/login", "", None,
                    "/a b", "/a\r\nX: y", f"http://127.0.0.1:{PORT + 7}/x", "http://127.0.0.1:99999/login"):
            with self.assertRaises(h1.HarnessError, msg=repr(bad)):
                h2.classify_location(bad, PORT)

    def test_location_helpers_never_expose_query(self):
        self.assertEqual(h2.location_path(f"{h2.REDIRECT_URI}?code=zzz"), "/callback")
        self.assertTrue(h2.location_has_code(f"{h2.REDIRECT_URI}?code=zzz"))
        self.assertFalse(h2.location_has_code("/login?error"))


class CookieJarTests(unittest.TestCase):
    def setUp(self):
        self.red = h1.Redactor()
        self.jar = h2.CookieJar(PORT, self.red)

    def test_scoping(self):
        self.jar.absorb([("Set-Cookie", "JSESSIONID=sessvalue0123456789; Path=/; HttpOnly"),
                         ("set-cookie", "XSRF=xsrfvalue0123456789; Path=/"), ("Location", "/login")])
        local = self.jar.header_for(f"http://127.0.0.1:{PORT}/login")
        self.assertIn("JSESSIONID=sessvalue0123456789", local)
        self.assertIn("XSRF=xsrfvalue0123456789", local)
        for other in (f"http://127.0.0.1:{PORT + 1}/login", f"http://localhost:{PORT}/login",
                      f"https://127.0.0.1:{PORT}/login", f"http://{ISSUER_HOST}:8084/login",
                      "http://127.0.0.1:9/callback"):
            self.assertIsNone(self.jar.header_for(other), other)

    def test_rotation_and_deletion(self):
        self.jar.absorb([("Set-Cookie", "JSESSIONID=old0123456789abcdef")])
        self.jar.absorb([("Set-Cookie", "JSESSIONID=new0123456789abcdef; Path=/")])
        self.assertEqual(self.jar.header_for(f"http://127.0.0.1:{PORT}/"), "JSESSIONID=new0123456789abcdef")
        self.jar.absorb([("Set-Cookie", "JSESSIONID=gone0123456789abcd; Max-Age=0")])
        self.assertIsNone(self.jar.header_for(f"http://127.0.0.1:{PORT}/"))
        self.jar.absorb([("Set-Cookie", "A=valueA0123456789"), ("Set-Cookie", "A=; Path=/"),
                         ("Set-Cookie", "bad cookie line")])
        self.assertEqual(self.jar.names(), [])

    def test_values_registered_with_redactor(self):
        self.jar.absorb([("Set-Cookie", "JSESSIONID=secretcookie0123456789; Path=/")])
        self.assertEqual(self.red.guard("x secretcookie0123456789 y"), "x <redacted> y")
        self.assertTrue(self.red.violation)


class HttpLayerTests(unittest.TestCase):
    def test_default_http_h2_returns_headers_and_does_not_follow(self):
        hdrs = http.client.HTTPMessage()
        hdrs["Location"] = "/login"
        hdrs["Set-Cookie"] = "A=1"
        hdrs["Set-Cookie"] = "B=2"
        err = urllib.error.HTTPError("http://127.0.0.1:41234/x", 302, "Found", hdrs, io.BytesIO(b"body"))

        class Opener:
            def open(self, req, timeout):
                self.req, self.timeout = req, timeout
                raise err

        op = Opener()
        status, headers, raw = h2.default_http_h2("GET", "http://127.0.0.1:41234/x", {"Accept": "text/html"},
                                                  None, 15, _opener=op)
        self.assertEqual((status, raw), (302, b"body"))
        self.assertEqual(h2.header_values(headers, "set-cookie"), ["A=1", "B=2"])
        self.assertEqual(op.timeout, 15)
        handlers = [type(x).__name__ for x in h1.build_opener().handlers]
        self.assertIn("_NoRedirect", handlers)

    def test_request_full_guards(self):
        r, out, server = make_runner()
        r.port = PORT
        with self.assertRaises(h1.AbortRun):          # no port-forward
            r.request_full("GET", "/login")
        r.pf = SeqProc(PORT)
        with self.assertRaises(h1.HarnessError):
            r.request_full("GET", "http://evil.example/x")
        server.overrides[("GET", "/oauth/authorize")] = resp(503, {"error": "down"})
        with self.assertRaises(h1.AbortRun):
            r.request_full("GET", "/oauth/authorize?state=SECRETSTATE&code_challenge=c")
        ev = events(out)[-1]
        self.assertEqual((ev["event"], ev["path"]), ("h2_http_5xx", "/oauth/authorize"))
        self.assertNotIn("SECRETSTATE", out.getvalue())


class EvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.v = full_vars()
        self.env = h2.EvalEnv(variables=self.v, exps={f"H2-P{i}": NOW + 900 for i in range(1, 7)},
                              request_time=NOW)
        self.env.sids.update({"H2-P1": "sid-p1", **{f"H2-P{i}": f"sid-prev-{i}" for i in range(2, 6)}})
        self.cases = h2.H2_EXPECTATIONS["cases"]

    def p1(self, status=200, token_type="Bearer", header=None, **over):
        body = json.dumps({"access_token": make_jwt(p1_claims(self.v, "sid-p1", **over), header),
                           "token_type": token_type})
        return h2.evaluate_token_response("H2-P1", self.cases["H2-P1"], status, body, self.env)

    def hop(self, n, status=200, itt=h1.ACCESS_TOKEN_TYPE, resp_auth="same", **over):
        claims = hop_claims(f"P{n}", self.v, NOW + 900, f"sid-{n}", **over)
        auth = claims.get("authority_id") if resp_auth == "same" else resp_auth
        body = json.dumps({"access_token": make_jwt(claims), "issued_token_type": itt, "authority_id": auth})
        return h2.evaluate_token_response(f"H2-P{n}", self.cases[f"H2-P{n}"], status, body, self.env)

    def test_all_positive_pass(self):
        self.assertEqual(self.p1()["result"], "pass", self.p1()["mismatches"])
        for n in range(2, 7):
            r = self.hop(n)
            self.assertEqual(r["result"], "pass", (n, r["mismatches"]))
            self.assertNotIn('"access_token"', json.dumps(r))
            self.assertNotIn(".c2lnbmF0dXJl", json.dumps(r))
            self.assertEqual(r["observed"]["claims"]["act"]["workload_id"], self.v[
                "bff_wl_id" if n <= 4 else "agent_wl_id"])

    def test_p1_fail_paths(self):
        for kw in ({"roles": []}, {"sid": None}, {"aud": ["x"]}, {"identity_kind": "workload"},
                   {"client_id": "x"}, {"sub": "other"}, {"tenant_id": "other"}, {"iss": "http://127.0.0.1"},
                   {"scope": ["openid"]}, {"status": 400}, {"token_type": "DPoP"}, {"header": {"typ": "JWT"}}):
            r = self.p1(**kw)
            self.assertEqual(r["result"], "fail", kw)

    def test_hop_fail_paths(self):
        bad = [
            (2, {"subject_sid": "other-sid"}), (2, {"authority_id": "route-x"}), (2, {"exp": NOW + 1000}),
            (2, {"act": {"sub": self.v["bff_wl_ref"], "client_id": self.v["bff_client"], "workload_id": "wl-x"}}),
            (2, {"azp": "x"}), (2, {"identity_kind": "workload"}), (2, {"scope": ["quickstart:invoke", "openid"]}),
            (2, {"token_use": "gateway_authorization"}), (2, {"iss": "x"}), (2, {"tenant_id": "x"}),
            (3, {"aud": [self.v["agent_aud"]]}), (3, {"authority_id": self.v["R2"]}), (3, {"token_use": "x"}),
            (3, {"subject_sid": None}), (3, {"client_id": self.v["broker_client"]}),
            (4, {"act": {"sub": f"agent:{PREFIX}-gateway-broker:test", "client_id": self.v["broker_client"]}}),
            (4, {"act": {"sub": self.v["bff_wl_ref"], "client_id": self.v["broker_client"]}}),
            (4, {"act": None}), (4, {"authority_id": self.v["R1"]}), (4, {"authority_profile": "x"}),
            (5, {"act": {"sub": self.v["bff_wl_ref"], "client_id": self.v["bff_client"]}}),
            (5, {"authority_id": self.v["R4"]}), (5, {"exp": NOW + 400}),
            (6, {"token_use": "exchange_subject"}), (6, {"aud": [self.v["tool_aud"], "x"]}),
            (6, {"azp": self.v["agent_client"]}), (6, {"subject_sid": "sid-6"}),
        ]
        for n, over in bad:
            r = self.hop(n, **over)
            self.assertEqual(r["result"], "fail", (n, over))
        self.assertEqual(self.hop(3, itt="urn:x")["result"], "fail")
        self.assertEqual(self.hop(3, status=400)["result"], "fail")

    def test_actor_replaced_by_broker_named(self):
        r = self.hop(4, act={"sub": f"agent:{PREFIX}-gateway-broker:test", "client_id": self.v["broker_client"]})
        joined = " ".join(r["mismatches"])
        self.assertIn("act.client_id must not be", joined)
        self.assertIn("act.sub contains gateway-broker", joined)

    def test_exp_bound_uses_previous_exp_and_request_time(self):
        self.env.exps["H2-P2"] = NOW + 100
        self.assertIn("exp", " ".join(self.hop(3)["mismatches"]))
        self.env.exps["H2-P2"] = NOW + 900
        r = self.hop(3, exp=NOW + 305, iat=NOW + 5)
        self.assertEqual((r["result"], r["observed"]["exp_bound"]), ("pass", NOW + 305))
        r = self.hop(3, exp=NOW + 306, iat=NOW + 6)
        self.assertEqual(r["mismatches"], [f"exp {NOW + 306} > bound {NOW + 305}"])
        self.env.request_time = NOW - 10
        r = self.hop(3, exp=NOW + 296, iat=NOW)
        self.assertEqual(r["mismatches"], [f"exp {NOW + 296} > bound {NOW + 295}"])
        del self.env.exps["H2-P2"]
        self.assertIn("H2-P2 exp unknown", self.hop(3)["mismatches"])

    def test_p1_contract_absences_and_exact_roles(self):
        bad = ({"azp": self.v["human_client"]}, {"act": {"sub": self.v["bff_wl_ref"]}}, {"token_use": "x"},
               {"subject_sid": "sid-x"}, {"roles": [self.v["operator_role"], "extra"]}, {"roles": None})
        for kw in bad:
            r = self.p1(**kw)
            self.assertEqual(r["result"], "fail", kw)
        self.assertIn("azp must be absent", self.p1(azp="x")["mismatches"])
        self.assertIn("act must be absent", self.p1(act={"sub": "x"})["mismatches"])

    def test_reviewer_hop_cases(self):
        v = self.v
        cases = [
            (5, {"client_id": v["bff_client"]}, "client_id mismatch"),
            (5, {"azp": v["broker_client"]}, "azp mismatch"),
            (2, {"authority_id": f"workforce:{v['bff_app_id']}:{v['user']}:1"}, "authority_id mismatch"),
            (2, {"authority_id": f"workforce:other-app:{v['user']}:2"}, "authority_id mismatch"),
            (3, {"sid": "sid-prev-2"}, "sid reused from ['H2-P2']"),
            (6, {"sid": "sid-p1"}, "sid reused from ['H2-P1']"),
            (3, {"iat": NOW - 100}, "exp-iat not in (0, 300]"),
            (4, {"roles": [v["operator_role"]]}, "roles must be absent"),
            (6, {"act": {"sub": v["agent_wl_ref"], "client_id": v["broker_client"],
                         "workload_id": v["agent_wl_id"]}}, "act.client_id mismatch"),
            (3, {"act": {"sub": v["bff_wl_ref"], "client_id": v["bff_client"]}}, "act.workload_id mismatch"),
            (2, {"identity_kind": "workload"}, "identity_kind mismatch"),
        ]
        for n, over, msg in cases:
            r = self.hop(n, **over)
            self.assertEqual(r["result"], "fail", (n, over))
            self.assertIn(msg, r["mismatches"], (n, over))
        r = self.hop(4, resp_auth="route-other")
        self.assertEqual(r["mismatches"], ["response authority_id != claim authority_id"])
        r = self.hop(4, resp_auth=None)
        self.assertEqual(r["result"], "fail")
        self.env.sids.pop("H2-P2")
        self.assertIn("previous sid unknown", self.hop(3)["mismatches"])

    def test_unknown_expected_value_fails(self):
        self.env.variables["p1_sid"] = None
        r = self.hop(2)
        self.assertEqual(r["result"], "fail")
        self.assertTrue(any("expected value unknown (p1_sid)" in m for m in r["mismatches"]))

    def test_non_json_and_undecodable(self):
        spec = self.cases["H2-P2"]
        self.assertEqual(h2.evaluate_token_response("H2-P2", spec, 200, "nope", self.env)["result"], "fail")
        r = h2.evaluate_token_response("H2-P2", spec, 200, json.dumps({"access_token": "a.b"}), self.env)
        self.assertEqual(r["result"], "fail")

    def test_denial_evaluator(self):
        spec = self.cases["H2-N6"]
        self.assertEqual(h2.evaluate_denial("H2-N6", spec, 400, '{"error":"invalid_target"}')["result"], "pass")
        for status, body in ((400, '{"error":"invalid_grant"}'), (401, '{"error":"invalid_target"}'),
                             (400, '{"error":"invalid_target","access_token":"t.t.t"}'), (400, "html")):
            self.assertEqual(h2.evaluate_denial("H2-N6", spec, status, body)["result"], "fail", body)

    def test_login_denial_evaluator(self):
        spec = self.cases["H2-N3"]
        ok = {"login_accepted": True, "final_status": 403, "code_issued": False, "trace": []}
        self.assertEqual(h2.evaluate_login_denial("H2-N3", spec, ok)["result"], "pass")
        for over in ({"code_issued": True}, {"final_status": 401}, {"login_accepted": False}):
            r = h2.evaluate_login_denial("H2-N3", spec, {**ok, **over})
            self.assertEqual(r["result"], "fail", over)
        r = h2.evaluate_login_denial("H2-N3", spec, {**ok, "code_issued": True, "final_status": 302})
        self.assertIn("authorization code issued", r["mismatches"])


class FullRunTests(unittest.TestCase):
    def assert_no_secrets(self, text, server, r):
        for s in server.secrets_seen + list(server.users.values()) + [p.reveal() for p in r.passwords.values()]:
            self.assertNotIn(s, text)
        self.assertNotIn("code=", text)
        self.assertNotIn("Basic ", text)

    def test_happy_path(self):
        code, evs, text, server, r = run_full()
        cs = cases_of(evs)
        self.assertEqual(list(cs), list(h2.CASE_IDS))
        for cid, c in cs.items():
            self.assertEqual(c["result"], "pass", (cid, c["mismatches"], c["observed"]))
        s = summary_of(evs)
        self.assertEqual(code, 0)
        self.assertEqual((s["passed"], s["failed"], s["skipped"], s["package"], s["redaction_violation"],
                          s["cleanup_complete"], s["port_forward_leaked"], s["aborted"]),
                         (15, 0, 0, "H-2", False, True, False, False))
        self.assertEqual(s["location_rewrites"], 0)
        for uid in (f"{PREFIX}-user", f"{PREFIX}-nomember"):
            self.assertLess(server.calls.index(("GET", f"/users/{uid}")),
                            [i for i, c in enumerate(server.calls) if c == ("POST", "/users")][
                                0 if uid.endswith("-user") else 1])
        self.assertTrue(all(e["event"].startswith("h2_") and e["package"] == "H-2" for e in evs))
        self.assert_no_secrets(text, server, r)
        self.assertEqual(server.bad_urls, [])
        self.assertNotIn(("GET", "/callback"), server.calls)
        # P1 sid propagated; per-hop sid differs
        self.assertEqual(cs["H2-P6"]["observed"]["claims"]["subject_sid"], cs["H2-P1"]["observed"]["claims"]["sid"])
        # authorization-code redemptions never carry Authorization; exchanges always Basic
        for req in server.requests:
            if req["path"] == "/oauth/token":
                form = dict(urllib.parse.parse_qsl(req["body"].decode()))
                self.assertEqual("Authorization" in req["headers"], form["grant_type"] != "authorization_code")
        # N2 never replays the P1 code: four redemptions with three distinct codes; P1's code redeemed once
        codes = [dict(urllib.parse.parse_qsl(q["body"].decode()))["code"] for q in server.requests
                 if q["path"] == "/oauth/token" and b"authorization_code" in q["body"]]
        self.assertEqual(len(codes), 4)
        self.assertEqual(codes.count(codes[0]), 1)
        self.assertEqual(codes[2], codes[3])
        # login hops: no Location URL printed, only paths and code_present
        p1 = cs["H2-P1"]["observed"]["login"]
        self.assertEqual([h["status"] for h in p1["trace"]], [302, 200, 302, 302])
        self.assertTrue(p1["trace"][-1]["code_present"])
        self.assertEqual(p1["trace"][-1]["location_path"], "/callback")
        n3 = cs["H2-N3"]["observed"]
        self.assertEqual((n3["final_status"], n3["code_issued"], n3["login_accepted"]), (403, False, True))
        # every exchange token had its own sid
        sids = {server.hop_claims[k]["sid"] for k in ("P1", "P2", "P3", "P4", "P5", "P6")}
        self.assertEqual(len(sids), 6)

    def test_setup_contract(self):
        code, evs, _text, server, _r = run_full()
        self.assertEqual(code, 0)
        reqs = [q for q in server.requests if q["method"] == "POST" and
                (q["path"].startswith("/admin/") or q["path"] == "/users") and q["body"]]
        bodies = [json.loads(q["body"]) for q in reqs]
        keys = [b["applicationKey"] for b in bodies if "applicationKey" in b]
        self.assertEqual(keys, [f"{PREFIX}-{x}" for x in ("bff", "gateway", "agent", "tool", "sibling")])
        clients = [(b["clientId"], b["clientType"]) for b in bodies if "clientType" in b]
        self.assertEqual(clients, [(f"{PREFIX}-human-web", "PUBLIC_BROWSER"), (f"{PREFIX}-bff", "CONFIDENTIAL_SERVICE"),
                                   (f"{PREFIX}-gateway-broker", "CONFIDENTIAL_SERVICE"),
                                   (f"{PREFIX}-agent", "CONFIDENTIAL_SERVICE"),
                                   (f"{PREFIX}-sibling", "CONFIDENTIAL_SERVICE")])
        routes = [(b["destinationType"], b["audience"]) for b in bodies if "destinationType" in b]
        self.assertEqual(routes, [("GATEWAY", f"{PREFIX}-gateway"), ("AGENT", f"agent:meridian:{PREFIX}-agent"),
                                  ("GATEWAY", f"{PREFIX}-gateway"), ("RESOURCE", f"tool:meridian:{PREFIX}-tool")])
        users = [b for b in bodies if "password" in b]
        self.assertEqual([u["id"] for u in users], [f"{PREFIX}-user", f"{PREFIX}-nomember"])
        self.assertTrue(all(u["password"].endswith("Aa1!") and u["email"].endswith("@phase0.invalid")
                            for u in users))
        order = [q["path"] for q in reqs]
        broker_i = next(i for i, p in enumerate(order) if p.endswith("/brokers"))
        route_i = next(i for i, p in enumerate(order) if p.endswith("/routes"))
        self.assertLess(broker_i, route_i)
        assign = [q for q in reqs if q["path"].endswith("/roles") and "/memberships/" in q["path"]]
        self.assertEqual(json.loads(assign[0]["body"])["assignmentSource"], "phase0-h2-test")
        first_login = next(i for i, q in enumerate(server.requests) if q["path"] == "/oauth/authorize")
        last_setup = max(i for i, q in enumerate(server.requests) if q["path"].endswith("/roles"))
        self.assertLess(last_setup, first_login)

    def test_tool_client_flag(self):
        code, evs, _t, server, _r = run_full(tool_needs_client=True)
        self.assertEqual(code, 0)
        self.assertIn(f"{PREFIX}-tool", server.clients)
        self.assertTrue(any(e["event"] == "h2_cleanup" and e["step"] == "disable_client:tool" and e["ok"]
                            for e in evs))

    def test_cleanup_order_and_sessions(self):
        code, evs, _t, server, _r = run_full()
        steps = [e["step"] for e in evs if e["event"] == "h2_cleanup"]
        sess_steps = [s for s in steps if s.startswith("revoke_sessions:user:")]
        self.assertEqual(len(sess_steps), 3)  # list + two sessions (P1 and the N2 first redemption)
        self.assertEqual(len(server.revoked_sessions), 2)
        expected_prefix_order = ["revoke_sessions:user", "revoke_sessions:nomember", "revoke_route:R4",
                                 "revoke_route:R3", "revoke_route:R2", "revoke_route:R1", "revoke_broker",
                                 "revoke_workload:bff", "revoke_workload:agent", "revoke_workload:sibling",
                                 "disable_client:human_web", "disable_client:bff", "disable_client:broker",
                                 "disable_client:agent", "disable_client:sibling", "remove_membership",
                                 "delete_user:user", "delete_user:nomember", "disable_application:bff",
                                 "disable_application:gateway", "disable_application:agent",
                                 "disable_application:tool", "disable_application:sibling"]
        seen = []
        for s in steps:
            head = s if not s.startswith("revoke_sessions") else ":".join(s.split(":")[:2])
            if head not in seen:
                seen.append(head)
        self.assertEqual(seen, expected_prefix_order)
        deletes = [p for m, p in server.calls if m == "DELETE"]
        self.assertTrue(any(p.startswith("/users/") for p in deletes))
        self.assertTrue(any("/access/memberships/" in p for p in deletes))
        self.assertTrue(all(e["ok"] for e in evs if e["event"] == "h2_cleanup"))

    def test_sessions_plain_list_shape(self):
        code, evs, _t, server, _r = run_full(FakeH2Server(session_list_shape="list"))
        self.assertEqual(code, 0)
        self.assertEqual(len(server.revoked_sessions), 2)

    def test_location_rewrite_from_issuer_host(self):
        code, evs, _t, server, _r = run_full(FakeH2Server(login_location="issuer"))
        self.assertEqual(code, 0)
        rewrites = [e for e in evs if e["event"] == "h2_location_rewrite"]
        self.assertTrue(rewrites)
        self.assertTrue(all(e["from_host"] == ISSUER_HOST and e["path"] in ("/login", "/oauth/authorize")
                            for e in rewrites))
        self.assertEqual(server.bad_urls, [])
        self.assertEqual(summary_of(evs)["location_rewrites"], len(rewrites))
        self.assertEqual(len(rewrites), 4)  # /login and saved /oauth/authorize, for each of the two logins

    def test_evil_host_with_known_path_rejected_not_requested(self):
        code, evs, text, server, _r = run_full(FakeH2Server(login_location="evil_login"))
        cs = cases_of(evs)
        self.assertEqual(code, 1)
        self.assertEqual(cs["H2-P1"]["result"], "fail")
        self.assertEqual(cs["H2-P1"]["observed"]["login"]["guard_reason"], "Location rejected: host not allowed")
        self.assertEqual(cs["H2-N3"]["result"], "fail")
        self.assertEqual(server.bad_urls, [])
        self.assertEqual(summary_of(evs)["location_rewrites"], 0)
        self.assertFalse(any(e["event"] == "h2_location_rewrite" for e in evs))
        self.assertNotIn("evil.example", text)

    def test_state_mismatch_fails_login_case_without_redeeming(self):
        s = FakeH2Server()
        s.tamper_state = True
        code, evs, _t, server, _r = run_full(s)
        cs = cases_of(evs)
        self.assertEqual(code, 1)
        self.assertEqual(cs["H2-P1"]["result"], "fail")
        self.assertIn("login: state mismatch", cs["H2-P1"]["mismatches"])
        self.assertFalse(cs["H2-P1"]["observed"]["login"]["state_ok"])
        self.assertEqual(server.redemptions, 0)
        self.assertEqual(cs["H2-N3"]["result"], "pass")

    def test_response_authority_mismatch_fails_integration(self):
        s = FakeH2Server()
        s.response_authority["P4"] = "route-other"
        code, evs, _t, _s, _r = run_full(s)
        cs = cases_of(evs)
        self.assertEqual(cs["H2-P4"]["mismatches"], ["response authority_id != claim authority_id"])
        self.assertEqual([cs[c]["result"] for c in ("H2-P5", "H2-N9", "H2-P6")], ["skipped"] * 3)
        self.assertEqual(code, 1)

    def test_user_precheck_existing_id_aborts_before_any_user_post(self):
        s = FakeH2Server()
        s.user_precheck_status = 200
        code, evs, _t, server, _r = run_full(s)
        self.assertEqual(code, 2)
        self.assertTrue(summary_of(evs)["aborted"])
        self.assertNotIn(("POST", "/users"), server.calls)
        self.assertIn(("GET", f"/users/{PREFIX}-user"), server.calls)
        self.assertTrue(any(e["event"] == "h2_setup" and e["step"] == "user_precheck:user" and not e["ok"]
                            for e in evs))
        self.assertFalse(any(m == "DELETE" and p.startswith("/users/") for m, p in server.calls))
        self.assertTrue(any(e["event"] == "h2_cleanup" and e["step"] == "disable_application:bff" and e["ok"]
                            for e in evs))
        self.assertEqual(summary_of(evs)["skipped"], 15)

    def test_returned_user_id_differs_aborts_setup(self):
        def other_id(headers, body):
            doc = json.loads(body)
            s.users[doc["id"]] = s._sensitive(doc["password"])
            return resp(201, {"id": doc["id"] + "-x", "username": doc["username"]})
        s = FakeH2Server(overrides={("POST", "/users"): other_id})
        code, evs, text, server, r = run_full(s)
        self.assertEqual(code, 2)
        self.assertTrue(summary_of(evs)["aborted"])
        self.assertEqual(server.calls.count(("POST", "/users")), 1)
        self.assertFalse(any(p.endswith("/access/memberships") for _m, p in server.calls))
        self.assertTrue(any(e["event"] == "h2_setup" and e.get("reason") == "returned id differs" for e in evs))
        self.assertNotIn("/oauth/authorize", [p for _m, p in server.calls])
        for p in r.passwords.values():
            self.assertNotIn(p.reveal(), text)
        # The account created under the server-returned id is still removed by cleanup.
        self.assertIn(("DELETE", f"/users/{PREFIX}-user-x"), server.calls)

    def test_entitlement_revision_taken_from_role_assignment_response(self):
        s = FakeH2Server()
        # Server reports revision 3: the harness must expect workforce:<app>:<user>:3, so the fake's ':2'
        # authority_id now fails P2 (proves the value comes from the server, not the constant).
        orig = s.__class__.__call__
        def patched(self_, method, url, headers, body, timeout):
            path = urllib.parse.urlsplit(url).path
            if method == "POST" and "/access/memberships/" in path and path.endswith("/roles"):
                self_.calls.append((method, path))
                return resp(200, {"id": path.split("/")[-2], "entitlementRevision": 3})
            return orig(self_, method, url, headers, body, timeout)
        with mock.patch.object(s.__class__, "__call__", patched):
            code, evs, text, server, r = run_full(s)
        self.assertTrue(any(e["event"] == "h2_setup" and e.get("step") == "membership_role"
                            and e.get("entitlementRevision") == 3 for e in evs))
        p2 = next(e for e in evs if e["event"] == "h2_case" and e["case_id"] == "H2-P2")
        self.assertEqual(p2["result"], "fail")
        self.assertIn("authority_id mismatch", p2["mismatches"])

    def test_login_5xx_aborts_redacts_password_and_cleans_up(self):
        def boom(headers, body):
            if body is None:
                return None
            form = dict(urllib.parse.parse_qsl(body.decode()))
            return resp(500, {"error": "server_error", "error_description": "failed for " + form["password"]})
        s = FakeH2Server(overrides={("POST", "/login"): boom})
        code, evs, text, server, r = run_full(s)
        self.assertEqual(code, 2)
        summ = summary_of(evs)
        self.assertTrue(summ["aborted"])
        self.assertTrue(summ["redaction_violation"])
        for p in r.passwords.values():
            self.assertNotIn(p.reveal(), text)
        self.assertTrue(any(e["event"] == "h2_http_5xx" and e["path"] == "/login" for e in evs))
        self.assertEqual(cases_of(evs)["H2-P1"]["result"], "skipped")
        cleanup = [e for e in evs if e["event"] == "h2_cleanup"]
        self.assertTrue(cleanup and all(e["ok"] for e in cleanup))
        self.assertTrue(summ["cleanup_complete"])

    def test_relative_locations(self):
        code, _evs, _t, _s, _r = run_full(FakeH2Server(login_location="relative"))
        self.assertEqual(code, 0)

    def test_foreign_redirect_rejected_not_requested(self):
        code, evs, text, server, _r = run_full(FakeH2Server(login_location="foreign"))
        cs = cases_of(evs)
        self.assertEqual(code, 1)
        self.assertEqual(cs["H2-P1"]["result"], "fail")
        self.assertEqual(cs["H2-P1"]["observed"]["login"]["guard_reason"], "Location rejected: host not allowed")
        self.assertEqual(cs["H2-N3"]["result"], "fail")
        self.assertEqual(server.bad_urls, [])
        self.assertNotIn("evil.example", text)

    def test_hop_limit(self):
        s = FakeH2Server()
        s.overrides[("GET", "/login")] = resp(302, None, [("Location", "/login")])
        code, evs, _t, server, _r = run_full(s)
        self.assertEqual(code, 1)
        self.assertEqual(cases_of(evs)["H2-P1"]["result"], "fail")
        self.assertLessEqual(server.calls.count(("GET", "/login")), 2 * h2.MAX_REDIRECT_HOPS)


class DenialIntegrationTests(unittest.TestCase):
    def check_only_failed(self, server, failed: set, skipped: set = frozenset()):
        code, evs, text, server, r = run_full(server)
        cs = cases_of(evs)
        for cid, c in cs.items():
            want = "fail" if cid in failed else "skipped" if cid in skipped else "pass"
            self.assertEqual(c["result"], want, (cid, c["mismatches"]))
        self.assertEqual(code, 1)
        return cs, evs, text

    def test_each_exchange_denial_wrong_error_fails(self):
        for n in ("N4", "N5", "N6", "N7", "N8", "N9"):
            s = FakeH2Server(exchange_overrides={n: (400, {"error": "invalid_request"})})
            cs, _evs, _t = self.check_only_failed(s, {f"H2-{n}"})
            self.assertTrue(any(m.startswith("error != ") for m in cs[f"H2-{n}"]["mismatches"]))

    def test_denial_that_issues_token_fails(self):
        tok = make_jwt({"sub": "x"})
        s = FakeH2Server(exchange_overrides={"N5": (200, {"access_token": tok})})
        cs, _e, text = self.check_only_failed(s, {"H2-N5"})
        self.assertIn("access_token present in denial body", cs["H2-N5"]["mismatches"])
        self.assertNotIn(tok, text)

    def test_n1_wrong_verifier_accepted_fails(self):
        s = FakeH2Server()
        s.allow_wrong_verifier = True
        self.check_only_failed(s, {"H2-N1"})

    def test_n2_replay_accepted_fails(self):
        s = FakeH2Server()
        s.allow_replay = True
        self.check_only_failed(s, {"H2-N2"})

    def test_n2_first_redemption_failure(self):
        s = FakeH2Server()
        s.redeem_fail_on = {3}
        cs, _e, _t = self.check_only_failed(s, {"H2-N2"})
        self.assertIn("first redemption status 400 != 200", cs["H2-N2"]["mismatches"])

    def test_n3_code_issued_fails(self):
        s = FakeH2Server()
        s.nomember_gets_code = True
        cs, _e, text = self.check_only_failed(s, {"H2-N3"})
        self.assertIn("authorization code issued", cs["H2-N3"]["mismatches"])
        self.assertNotIn("code=", text)

    def test_n3_other_status_recorded(self):
        s = FakeH2Server()
        s.nomember_status = 401
        cs, _e, _t = self.check_only_failed(s, {"H2-N3"})
        self.assertEqual(cs["H2-N3"]["observed"]["final_status"], 401)
        self.assertFalse(cs["H2-N3"]["observed"]["code_issued"])


class DependencyTests(unittest.TestCase):
    def test_p1_failure_skips_dependents_but_not_n3(self):
        code, evs, _t, _s, _r = run_full(FakeH2Server(claim_overrides={"P1": {"roles": []}}))
        cs = cases_of(evs)
        self.assertEqual(cs["H2-P1"]["result"], "fail")
        self.assertEqual(cs["H2-N3"]["result"], "pass")
        for cid in h2.CASE_IDS:
            if cid not in ("H2-P1", "H2-N3"):
                self.assertEqual(cs[cid]["result"], "skipped", cid)
        self.assertIn("H2-P1", cs["H2-N1"]["observed"]["skipped_reason"])
        self.assertEqual(code, 1)

    def test_p3_subject_sid_mismatch_skips_chain(self):
        code, evs, _t, _s, _r = run_full(FakeH2Server(claim_overrides={"P3": {"subject_sid": "sid-other"}}))
        cs = cases_of(evs)
        self.assertEqual(cs["H2-P3"]["result"], "fail")
        self.assertIn("subject_sid mismatch", cs["H2-P3"]["mismatches"])
        for cid in ("H2-N8", "H2-P4", "H2-P5", "H2-N9", "H2-P6"):
            self.assertEqual(cs[cid]["result"], "skipped", cid)
        for cid in ("H2-P1", "H2-N1", "H2-N2", "H2-N3", "H2-P2", "H2-N4", "H2-N5", "H2-N6", "H2-N7"):
            self.assertEqual(cs[cid]["result"], "pass", cid)
        self.assertEqual(code, 1)

    def test_p4_actor_replaced_by_broker(self):
        act = {"sub": f"agent:{PREFIX}-gateway-broker:test", "client_id": f"{PREFIX}-gateway-broker"}
        code, evs, _t, _s, _r = run_full(FakeH2Server(claim_overrides={"P4": {"act": act}}))
        cs = cases_of(evs)
        self.assertEqual(cs["H2-P4"]["result"], "fail")
        self.assertEqual([cs[c]["result"] for c in ("H2-P5", "H2-N9", "H2-P6")], ["skipped"] * 3)
        self.assertEqual(code, 1)

    def test_wrong_authority_aud_token_use_exp(self):
        for hop, over, cid in (("P6", {"authority_id": "route-x"}, "H2-P6"),
                               ("P5", {"aud": ["other"]}, "H2-P5"),
                               ("P2", {"token_use": "delegated_access"}, "H2-P2"),
                               ("P4", {"exp": NOW + 10_000}, "H2-P4")):
            code, evs, _t, _s, _r = run_full(FakeH2Server(claim_overrides={hop: over}))
            self.assertEqual(cases_of(evs)[cid]["result"], "fail", hop)
            self.assertEqual(code, 1)


class RedactionTests(unittest.TestCase):
    def test_echoed_code_is_redacted_and_forces_exit_2(self):
        s = FakeH2Server()
        s.echo_code_on_replay = True
        code, evs, text, server, _r = run_full(s)
        self.assertEqual(code, 2)
        self.assertTrue(summary_of(evs)["redaction_violation"])
        self.assertIn("<redacted>", text)
        for c in server.codes:
            self.assertNotIn(c, text)

    def test_password_echoed_in_setup_error_redacted(self):
        def echo(headers, body):
            doc = json.loads(body)
            return resp(400, {"error": "bad", "error_description": "rejected " + doc["password"]})
        s = FakeH2Server(overrides={("POST", "/users"): echo})
        code, evs, text, server, r = run_full(s)
        self.assertEqual(code, 2)
        self.assertTrue(summary_of(evs)["aborted"])
        self.assertTrue(summary_of(evs)["redaction_violation"])
        for p in r.passwords.values():
            self.assertNotIn(p.reveal(), text)
        # cleanup still ran for created objects
        self.assertTrue(any(e["event"] == "h2_cleanup" and e["step"] == "disable_application:bff" for e in evs))

    def test_registered_sensitive_kinds(self):
        r, _out, _s = make_runner()
        code = r.run()
        self.assertEqual(code, 0)
        text = "|".join(sorted(r.redactor._values))
        jar_values = [v for j in r.jars.values() for v in j._cookies.values()]
        self.assertTrue(jar_values)
        for v in jar_values:
            self.assertIn(v, text)
        for p in r.passwords.values():
            self.assertIn(p.reveal(), text)
        self.assertTrue(_s.states_seen)
        for st in _s.states_seen:   # state and nonce of every authorize
            self.assertIn(st, text)


class CleanupRobustnessTests(unittest.TestCase):
    def test_failed_step_continues_and_exit_2(self):
        s = FakeH2Server()
        orig = s.admin

        def admin(method, path, query, body, base):
            if method == "POST" and path.endswith("/revoke") and "/routes/" in path and path.split("/")[-2] == s.routes[2]:
                return resp(500, {"error": "boom"})
            return orig(method, path, query, body, base)
        s.admin = admin
        code, evs, _t, _s, _r = run_full(s)
        cleanup = {e["step"]: e for e in evs if e["event"] == "h2_cleanup"}
        self.assertFalse(cleanup["revoke_route:R3"]["ok"])
        self.assertTrue(cleanup["revoke_route:R2"]["ok"])
        self.assertTrue(cleanup["disable_application:sibling"]["ok"])
        s_ = summary_of(evs)
        self.assertEqual((s_["passed"], s_["cleanup_complete"], code), (15, False, 2))

    def test_unexpected_exception_does_not_stop_remaining_steps(self):
        s = FakeH2Server()

        def boom(headers, body):
            raise RuntimeError("secret detail")
        s.overrides[("DELETE", f"/users/{PREFIX}-user")] = boom
        code, evs, text, _s, _r = run_full(s)
        cleanup = {e["step"]: e for e in evs if e["event"] == "h2_cleanup"}
        self.assertEqual(cleanup["delete_user:user"]["reason"], "unexpected RuntimeError")
        self.assertTrue(cleanup["delete_user:nomember"]["ok"])
        self.assertTrue(cleanup["disable_application:bff"]["ok"])
        self.assertNotIn("secret detail", text)
        self.assertEqual(code, 2)

    def test_relogin_once_on_401(self):
        s = FakeH2Server()
        state = {"n": 0}

        def first_401(headers, body):
            state["n"] += 1
            return resp(401, {"error": "expired"}) if state["n"] == 1 else None
        s.overrides[("POST", f"/admin/tenants/meridian/agent-exchange/routes/route-0016/revoke")] = first_401
        code, evs, _t, _s, _r = run_full(s)
        self.assertTrue(any(e["event"] == "h2_cleanup_relogin" and e["ok"] for e in evs))
        self.assertEqual(code, 0, [e for e in evs if e["event"] == "h2_cleanup" and not e["ok"]])

    def test_unsafe_ids_never_used(self):
        r, out, server = make_runner()
        r.port = PORT
        r.pf = SeqProc(PORT)
        r.admin_token = h1.SensitiveValue(server.admin_token)
        r.h2.users = {"user": "bad/../id"}
        r.h2.membership = "mem/../../x"
        r.h2.apps = {"bff": "app-1"}
        r.h2.routes = {"R1": "route 1"}
        r.cleanup()
        evs = events(out)
        bad = [e for e in evs if e.get("reason") == "unsafe server id"]
        self.assertEqual({e["step"] for e in bad}, {"revoke_sessions:user", "revoke_route:R1", "remove_membership",
                                                     "delete_user:user"})
        self.assertTrue(r.cleanup_incomplete)
        self.assertFalse(any(".." in p or " " in p for _m, p in server.calls))

    def test_session_revision_must_be_integer(self):
        r, out, server = make_runner()
        r.port, r.pf = PORT, SeqProc(PORT)
        r.admin_token = h1.SensitiveValue(server.admin_token)
        r.h2.users = {"user": f"{PREFIX}-user"}
        server.iam_sessions = [{"id": "sess-1", "principalId": f"{PREFIX}-user", "status": "ACTIVE",
                                "revision": "3"}]
        r.cleanup()
        self.assertTrue(r.cleanup_incomplete)
        self.assertEqual(server.revoked_sessions, [])

    def test_port_forward_lost_mid_run_restarts_for_cleanup(self):
        s = FakeH2Server()
        holder = {}
        ports = iter([PORT, PORT2])

        def kill():
            holder["r"].pf.returncode = 1
        s.pf_killer = kill
        popen = SeqPopen([PORT, PORT2])
        r, out, server = make_runner(s, popen=popen, port_chooser=lambda: next(ports))
        holder["r"] = r
        code = r.run()
        evs = events(out)
        self.assertEqual(code, 2)
        self.assertTrue(any(e["event"] == "h2_port_forward_restart" and e["ok"] for e in evs))
        self.assertTrue(summary_of(evs)["cleanup_complete"])
        self.assertEqual(len(popen.calls), 2)
        self.assertIn(("POST", "/users"), server.calls)
        self.assertTrue(any(m == "DELETE" and p.startswith("/users/") for m, p in server.calls))

    def test_5xx_in_case_aborts_and_cleans_up(self):
        s = FakeH2Server(exchange_overrides={"P3": (502, {"error": "bad_gateway"})})
        code, evs, _t, server, _r = run_full(s)
        cs = cases_of(evs)
        self.assertEqual(code, 2)
        self.assertEqual(cs["H2-P3"]["result"], "fail")
        self.assertEqual(cs["H2-P6"]["observed"]["skipped_reason"], "aborted")
        self.assertTrue(summary_of(evs)["aborted"])
        self.assertTrue(summary_of(evs)["cleanup_complete"])

    def test_verification_failure_makes_no_admin_writes(self):
        r, out, server = make_runner()
        r.run_cmd = FakeCmd(**{"V-2": h1.subprocess.CompletedProcess([], 1, "", "nope")})
        code = r.run()
        self.assertEqual(code, 2)
        self.assertEqual(server.calls, [])
        self.assertEqual(summary_of(events(out))["skipped"], 15)


class PlanModeTests(unittest.TestCase):
    def test_plan_mode_makes_no_calls(self):
        buf = io.StringIO()
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("run")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("popen")), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("socket")), \
                mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("urlopen")), \
                mock.patch.object(urllib.request.OpenerDirector, "open", side_effect=AssertionError("open")), \
                mock.patch.object(h2.H2Runner, "__init__", side_effect=AssertionError("runner")):
            self.assertEqual(h2.main(["--package", "h2"], out=buf), 0)
        evs = [json.loads(l) for l in buf.getvalue().splitlines()]
        self.assertEqual(evs[0]["event"], "h2_plan")
        self.assertEqual(len([e for e in evs if e["event"] == "h2_plan_verify"]), 11)
        plan_cases = [e for e in evs if e["event"] == "h2_plan_case"]
        self.assertEqual([e["case_id"] for e in plan_cases], list(h2.CASE_IDS))
        self.assertEqual(evs[-1]["event"], "h2_plan_cleanup")
        self.assertTrue(all(e["package"] == "H-2" for e in evs))
        p6 = plan_cases[-1]
        self.assertEqual(p6["audience"], "tool:meridian:<p>-tool")
        self.assertIn(["claim", "authority_id", "<R4>"], p6["checks"])

    def test_package_flag_required(self):
        with mock.patch("sys.stderr", io.StringIO()):
            for argv in ([], ["--package", "h1"], ["--execute"]):
                with self.assertRaises(SystemExit, msg=argv):
                    h2.main(argv, out=io.StringIO())

    def test_execute_uses_runner_and_installs_signals(self):
        class R:
            def __init__(self, out):
                self.out = out

            def run(self):
                return 7
        with mock.patch.object(h2.signal, "signal") as sig:
            self.assertEqual(h2.main(["--package", "h2", "--execute"], out=io.StringIO(), runner_factory=R), 7)
        self.assertEqual({c.args[0] for c in sig.call_args_list}, {h2.signal.SIGTERM, h2.signal.SIGHUP})


if __name__ == "__main__":
    unittest.main()
