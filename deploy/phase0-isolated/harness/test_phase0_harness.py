"""Unit tests for phase0_harness (H-1). No real subprocess, cluster or network access."""

from __future__ import annotations

import base64
import io
import json
import subprocess
import time
import unittest
import urllib.error
import urllib.parse
from unittest import mock

import phase0_harness as h

PREFIX = "p0habcdef0123"
PORT = 41234
PASSWORD = "Adm1n-Test-Pa$$\"word"
ROUTE_ID = "route-0001"
ENTRY_WL_ID = "wl-entry-0001"
NS_TS = "2026-10-01T10:00:00Z"
SECRET_TS = "2026-10-01T10:00:05Z"


def b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def make_jwt(payload: dict, header: dict | None = None) -> str:
    header = header if header is not None else {"alg": "RS256", "typ": "at+jwt", "kid": "k1"}
    return f"{b64url(header)}.{b64url(payload)}.c2lnbmF0dXJl"


def p1_claims(now: int, **over) -> dict:
    c = {"iss": h.EXPECTED_ISSUER, "sub": f"{PREFIX}-entry", "client_id": f"{PREFIX}-entry",
         "aud": [f"agent:meridian:{PREFIX}-entry"], "identity_kind": "workload", "tenant_id": "meridian",
         "scope": ["quickstart:invoke"], "iat": now, "exp": now + 3600}
    c.update(over)
    return c


def p2_claims(now: int, p1_exp: int, **over) -> dict:
    c = {"iss": h.EXPECTED_ISSUER, "sub": f"{PREFIX}-entry", "aud": f"{PREFIX}-gateway",
         "act": {"sub": f"agent:{PREFIX}-entry:test", "client_id": f"{PREFIX}-entry", "workload_id": ENTRY_WL_ID},
         "client_id": f"{PREFIX}-entry", "azp": f"{PREFIX}-entry", "identity_kind": "workload", "sid": "s-1",
         "authority_profile": "workload_continuation", "token_use": "gateway_authorization",
         "authority_id": ROUTE_ID, "scope": "quickstart:invoke", "iat": now, "exp": min(p1_exp, now + 300)}
    c.update(over)
    return c


def admin_claims(**over) -> dict:
    c = {"iss": h.EXPECTED_ISSUER, "tenant_id": "meridian", "aud": ["axiom-api"], "roles": ["platform_admin"],
         "sub": "admin"}
    c.update(over)
    return c


# ---------------------------------------------------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------------------------------------------------

class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def good_ns():
    return json.dumps({"metadata": {"name": h.NAMESPACE, "creationTimestamp": NS_TS,
                                    "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}})


def good_helm():
    return json.dumps([{"name": "axiom", "namespace": h.NAMESPACE, "chart": "axiom-0.1.3", "status": "deployed"}])


def good_pods():
    return json.dumps({"items": [{"metadata": {"name": "axiom-server-1", "namespace": h.NAMESPACE},
                                  "status": {"conditions": [{"type": "Ready", "status": "True"}],
                                             "containerStatuses": [{"name": "server", "ready": True,
                                                                    "imageID": "docker.io/x@" + h.EXPECTED_DIGEST}]}}]})


def good_secret_meta():
    return f"{h.NAMESPACE}\n{SECRET_TS}\naxiom.bootstrap.admin-password\naxiom.db.password\n"


class FakeCmd:
    def __init__(self, **over):
        self.calls = []
        self.out = {"V-1": FakeCompleted(0, "CURRENT   NAME             CLUSTER\n*         docker-desktop   docker-desktop\n"),
                    "V-2": FakeCompleted(0, good_ns()),
                    "V-3": FakeCompleted(0, good_helm()),
                    "V-4": FakeCompleted(0, good_pods()),
                    "V-5": FakeCompleted(0, good_secret_meta()),
                    "V-5v": FakeCompleted(0, base64.b64encode(PASSWORD.encode()).decode() + "\n")}
        self.out.update(over)

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        if argv[:3] == ["kubectl", "config", "get-contexts"]:
            return self.out["V-1"]
        if "ns" in argv:
            return self.out["V-2"]
        if argv[0] == "helm":
            return self.out["V-3"]
        if "pods" in argv:
            return self.out["V-4"]
        if "secret" in argv and any(a.startswith("go-template=") for a in argv):
            return self.out["V-5"]
        if "secret" in argv and any(a.startswith("jsonpath=") for a in argv):
            return self.out["V-5v"]
        raise AssertionError(f"unexpected argv {argv}")


class FakeProc:
    def __init__(self, port=PORT, die_after_start=False):
        self.stdout = iter([f"Forwarding from 127.0.0.1:{port} -> 8084\n"])
        self.returncode = None
        self.die_after_start = die_after_start
        self.polls = 0
        self.terminated = False

    def poll(self):
        self.polls += 1
        if self.die_after_start and self.polls > 1:
            self.returncode = 1
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class FakePopen:
    def __init__(self, **kw):
        self.calls = []
        self.kw = kw
        self.proc = None

    def __call__(self, argv):
        self.calls.append(list(argv))
        self.proc = FakeProc(**self.kw)
        return self.proc


class FakeServer:
    """Routes harness HTTP calls; records (method, path)."""

    def __init__(self, now: int, overrides: dict | None = None):
        self.now = now
        self.calls: list[tuple[str, str]] = []
        self.overrides = overrides or {}
        self.n = 0
        self.secrets = {}
        self.p1_token = make_jwt(p1_claims(now))
        self.p2_token = make_jwt(p2_claims(now, now + 3600))
        self.admin_token = make_jwt(admin_claims(), {"alg": "RS256"})

    def _id(self, kind):
        self.n += 1
        return f"{kind}-{self.n:04d}"

    def __call__(self, method, url, headers, body, timeout):
        assert url.startswith(f"http://127.0.0.1:{PORT}/"), url
        path = urllib.parse.urlsplit(url).path
        self.calls.append((method, path))
        key = (method, path)
        if key in self.overrides:
            r = self.overrides[key]
            return r(headers, body) if callable(r) else r
        base = "/admin/tenants/meridian"
        if key == ("GET", "/.well-known/openid-configuration"):
            return 200, json.dumps({"issuer": h.EXPECTED_ISSUER,
                                    "token_endpoint": "http://evil.example/token",
                                    "grant_types_supported": ["client_credentials", h.TOKEN_EXCHANGE_GRANT]}).encode()
        if key == ("GET", "/.well-known/oauth-authorization-server"):
            return 200, json.dumps({"issuer": h.EXPECTED_ISSUER,
                                    "grant_types_supported": ["client_credentials", h.TOKEN_EXCHANGE_GRANT]}).encode()
        if key == ("GET", "/actuator/health/readiness"):
            return 200, b'{"status":"UP"}'
        if key == ("POST", "/auth/login"):
            doc = json.loads(body)
            if doc != {"username": "admin", "password": PASSWORD}:
                return 401, b'{"error":"bad"}'
            return 200, json.dumps({"accessToken": self.admin_token}).encode()
        if method != "POST" or path != "/oauth/token":
            assert headers.get("Authorization") == "Bearer " + self.admin_token
        if key == ("GET", f"{base}/applications"):
            return 200, json.dumps({"content": [{"applicationKey": "quickstart-agent"}]}).encode()
        if key == ("POST", f"{base}/applications"):
            return 201, json.dumps({"id": self._id("app")}).encode()
        if method == "POST" and path.startswith(f"{base}/applications/") and path.endswith("/clients"):
            cid = json.loads(body)["clientId"]
            secret = f"svc-secret-{cid}-XYZ"
            self.secrets[cid] = secret
            return 201, json.dumps({"client": {"id": self._id("client"), "clientId": cid},
                                    "serviceSecret": secret}).encode()
        if key == ("POST", f"{base}/ciam/agent-workloads"):
            wl = ENTRY_WL_ID if json.loads(body)["oauthClientId"].endswith("-entry") else self._id("wl")
            return 201, json.dumps({"id": wl}).encode()
        if key == ("POST", f"{base}/agent-exchange/brokers"):
            return 201, json.dumps({"id": self._id("broker")}).encode()
        if key == ("POST", f"{base}/agent-exchange/routes"):
            doc = json.loads(body)
            assert doc["expiresAt"].endswith("Z") and doc["destinationType"] == "GATEWAY"
            return 201, json.dumps({"id": ROUTE_ID}).encode()
        if path.endswith("/revoke") or method == "DELETE":
            return 204, b""
        if key == ("POST", "/oauth/token"):
            return self.token(headers, body)
        raise AssertionError(f"unexpected {method} {path}")

    def token(self, headers, body):
        auth = headers["Authorization"]
        assert auth.startswith("Basic ")
        cid, secret = base64.b64decode(auth[6:]).decode().split(":", 1)
        cid, secret = urllib.parse.unquote_plus(cid), urllib.parse.unquote_plus(secret)
        if self.secrets.get(cid) != secret:
            return 401, b'{"error":"invalid_client"}'
        form = dict(urllib.parse.parse_qsl(body.decode()))
        if form["grant_type"] == "client_credentials":
            return 200, json.dumps({"access_token": self.p1_token, "token_type": "Bearer",
                                    "expires_in": 3600}).encode()
        assert form["subject_token"] == self.p1_token
        if cid.endswith("-sibling"):
            return 400, b'{"error":"invalid_grant","error_description":"subject not owned"}'
        if form["audience"].startswith("agent:"):
            return 400, b'{"error":"invalid_target"}'
        if len(form["scope"].split()) > 1:
            return 400, b'{"error":"invalid_scope"}'
        return 200, json.dumps({"access_token": self.p2_token, "issued_token_type": h.ACCESS_TOKEN_TYPE,
                                "token_type": "Bearer", "authority_id": ROUTE_ID}).encode()


def make_runner(cmd=None, popen=None, server=None, now=None, port=PORT):
    now = now if now is not None else int(time.time())
    out = io.StringIO()
    cmd = cmd or FakeCmd()
    popen = popen or FakePopen()
    server = server or FakeServer(now)
    r = h.Runner(run_cmd=cmd, popen=popen, http=server, out=out, now=lambda: now, prefix=PREFIX,
                 port_chooser=lambda: port, pf_ready_timeout=2.0)
    return r, out, cmd, popen, server


def events(out: io.StringIO) -> list[dict]:
    return [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]


def admin_writes(server: FakeServer) -> list:
    return [c for c in server.calls if c[0] in ("POST", "DELETE") and c[1].startswith("/admin/")]


# ---------------------------------------------------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------------------------------------------------

class CommandBuilderTests(unittest.TestCase):
    def test_kubectl_injects_context_and_namespace(self):
        argv = h.build_command("kubectl", "get", "pods", "-o", "json")
        self.assertEqual(argv, ["kubectl", "--context", "docker-desktop", "get", "-n", "axiom-phase0-test",
                                "pods", "-o", "json"])

    def test_helm_injects_kube_context_and_namespace(self):
        self.assertEqual(h.build_command("helm", "list", "-o", "json"),
                         ["helm", "--kube-context", "docker-desktop", "list", "-n", "axiom-phase0-test", "-o", "json"])

    def test_port_forward_template(self):
        argv = h.build_command("kubectl", "port-forward", "svc/axiom", "41234:8084", "--address", "127.0.0.1")
        self.assertEqual(argv[:6], ["kubectl", "--context", "docker-desktop", "port-forward", "-n",
                                    "axiom-phase0-test"])

    def test_rejects_other_namespace_and_context(self):
        for ns in ("axiom", "default", "kube-system", ""):
            with self.assertRaises(h.HarnessError):
                h.build_command("kubectl", "get", "pods", namespace=ns)
        with self.assertRaises(h.HarnessError):
            h.build_command("kubectl", "get", "pods", context="prod")
        with self.assertRaises(h.HarnessError):
            h.build_context_check_command("kind-kind")

    def test_rejects_forbidden_args(self):
        for bad in ("-A", "--all-namespaces", "axiom", "-n", "--namespace", "--namespace=axiom", "--context",
                    "--context=x", "--kube-context", "--kubeconfig=/tmp/x"):
            with self.assertRaises(h.HarnessError, msg=bad):
                h.build_command("kubectl", "get", "pods", bad)
        with self.assertRaises(h.HarnessError):
            h.build_command("kubectl", "-A", "pods")
        with self.assertRaises(h.HarnessError):
            h.build_command("kubectl", "config", "view")
        with self.assertRaises(h.HarnessError):
            h.build_command("bash", "get")

    def test_context_check_command(self):
        self.assertEqual(h.build_context_check_command(), ["kubectl", "config", "get-contexts", "docker-desktop"])

    def test_default_run_cmd_uses_list_no_shell(self):
        with mock.patch.object(subprocess, "run") as run:
            run.return_value = FakeCompleted()
            h.default_run_cmd(["kubectl", "--context", "docker-desktop"], 7)
            _args, kwargs = run.call_args
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["capture_output"])
            self.assertEqual(kwargs["timeout"], 7)
        with self.assertRaises(h.HarnessError):
            h.default_run_cmd("kubectl get pods")


class JwtAndClaimTests(unittest.TestCase):
    def test_decode_roundtrip(self):
        hdr, payload = h.decode_jwt(make_jwt({"a": 1}))
        self.assertEqual(hdr["typ"], "at+jwt")
        self.assertEqual(payload, {"a": 1})

    def test_decode_rejects_bad(self):
        for bad in (None, "", "a.b", "a.b.c.d", "!!!.###.x", b64url([1]) + "." + b64url({}) + ".s"):
            with self.assertRaises(ValueError):
                h.decode_jwt(bad)

    def test_normalizers(self):
        self.assertEqual(h.normalize_aud("x"), ["x"])
        self.assertEqual(h.normalize_aud(["x", "y"]), ["x", "y"])
        self.assertIsNone(h.normalize_aud(5))
        self.assertEqual(h.normalize_scope("a b"), {"a", "b"})
        self.assertEqual(h.normalize_scope(["a", "b c"]), {"a", "b", "c"})
        self.assertIsNone(h.normalize_scope(None))
        self.assertEqual(h.normalize_roles("platform_admin,x"), {"platform_admin", "x"})

    def test_filter_claims_allow_list(self):
        f = h.filter_claims({"sub": "s", "email": "e@x", "act": {"sub": "a", "secret": "z"}, "roles": ["r"]})
        self.assertEqual(f, {"sub": "s", "act": {"sub": "a"}})

    def test_basic_auth_form_encodes(self):
        hdr = h.basic_auth("a b:c", "p+q/r")
        raw = base64.b64decode(hdr[6:]).decode()
        self.assertEqual(raw, "a+b%3Ac:p%2Bq%2Fr")


class EvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.ctx = h.CaseContext(prefix=PREFIX, route_id=ROUTE_ID, p1_exp=self.now + 3600, now=lambda: self.now)

    def p1_body(self, **over):
        return json.dumps({"access_token": make_jwt(p1_claims(self.now, **over)), "token_type": "bearer"})

    def test_p1_pass(self):
        r = h.evaluate_p1(200, self.p1_body(), self.ctx)
        self.assertEqual(r["result"], "pass", r["mismatches"])
        self.assertNotIn("access_token", json.dumps(r))
        self.assertEqual(len(r["observed"]["token_sha256_12"]), 12)

    def test_p1_fail_paths(self):
        cases = [
            (200, self.p1_body(aud=["other"])),
            (200, self.p1_body(sid="abc")),
            (200, self.p1_body(exp=self.now + 7200)),
            (200, self.p1_body(scope="quickstart:invoke cards:incident.read")),
            (200, self.p1_body(identity_kind="human")),
            (200, self.p1_body(iss="http://127.0.0.1:41234")),
            (200, self.p1_body(client_id="x")),
            (400, json.dumps({"error": "invalid_client"})),
            (200, "not json"),
            (200, json.dumps({"access_token": "x.y", "token_type": "Bearer"})),
            (200, json.dumps({"access_token": make_jwt(p1_claims(self.now), {"typ": "JWT"}),
                              "token_type": "Bearer"})),
            (200, json.dumps({"access_token": make_jwt(p1_claims(self.now)), "token_type": "DPoP"})),
        ]
        for status, body in cases:
            r = h.evaluate_p1(status, body, self.ctx)
            self.assertEqual(r["result"], "fail", (status, body))

    def p2_body(self, resp_auth=ROUTE_ID, **over):
        return json.dumps({"access_token": make_jwt(p2_claims(self.now, self.now + 3600, **over)),
                           "issued_token_type": h.ACCESS_TOKEN_TYPE, "authority_id": resp_auth})

    def test_p2_pass(self):
        r = h.evaluate_p2(200, self.p2_body(), self.ctx)
        self.assertEqual(r["result"], "pass", r["mismatches"])

    def test_p2_fail_paths(self):
        bodies = [
            self.p2_body(resp_auth="other"),
            self.p2_body(authority_id="other"),
            self.p2_body(exp=self.now + 1000),
            self.p2_body(act=None),
            self.p2_body(act={"sub": "agent:x:test", "client_id": f"{PREFIX}-entry"}),
            self.p2_body(aud=[f"{PREFIX}-gateway", "extra"]),
            self.p2_body(token_use="other"),
            self.p2_body(authority_profile="delegated"),
            self.p2_body(azp="someone-else"),
            self.p2_body(client_id="someone-else"),
            self.p2_body(identity_kind="workforce"),
            self.p2_body(scope=["quickstart:invoke", "cards:incident.read"]),
            json.dumps({"access_token": make_jwt(p2_claims(self.now, self.now + 3600)),
                        "issued_token_type": "urn:ietf:params:oauth:token-type:jwt", "authority_id": ROUTE_ID}),
        ]
        for body in bodies:
            self.assertEqual(h.evaluate_p2(200, body, self.ctx)["result"], "fail", body)
        self.assertEqual(h.evaluate_p2(400, self.p2_body(), self.ctx)["result"], "fail")
        # act.workload_id is asserted when the entry workload id is known
        ctx_wl = h.CaseContext(prefix=PREFIX, route_id=ROUTE_ID, p1_exp=self.now + 3600, now=lambda: self.now,
                               entry_workload_id=ENTRY_WL_ID)
        self.assertEqual(h.evaluate_p2(200, self.p2_body(), ctx_wl)["result"], "pass")
        wrong_wl = self.p2_body(act={"sub": f"agent:{PREFIX}-entry:test", "client_id": f"{PREFIX}-entry",
                                     "workload_id": "wl-other"})
        self.assertEqual(h.evaluate_p2(200, wrong_wl, ctx_wl)["result"], "fail")
        # sid is recorded, not asserted
        self.assertTrue(h.evaluate_p2(200, self.p2_body(), self.ctx)["observed"]["sid_present"])
        # exp bound also limited by P1 exp
        ctx = h.CaseContext(prefix=PREFIX, route_id=ROUTE_ID, p1_exp=self.now + 100, now=lambda: self.now)
        self.assertEqual(h.evaluate_p2(200, self.p2_body(exp=self.now + 200), ctx)["result"], "fail")

    def test_denials(self):
        pairs = [(h.evaluate_n1, "invalid_target"), (h.evaluate_n2, "invalid_grant"), (h.evaluate_n3, "invalid_scope")]
        for fn, err in pairs:
            ok = fn(400, json.dumps({"error": err, "error_description": "d"}), self.ctx)
            self.assertEqual(ok["result"], "pass")
            self.assertEqual(ok["observed"]["error_description"], "d")
            self.assertEqual(fn(400, json.dumps({"error": "invalid_request"}), self.ctx)["result"], "fail")
            self.assertEqual(fn(401, json.dumps({"error": err}), self.ctx)["result"], "fail")
            self.assertEqual(fn(400, "<html>", self.ctx)["result"], "fail")
            leaked = fn(400, json.dumps({"error": err, "access_token": "tok"}), self.ctx)
            self.assertEqual(leaked["result"], "fail")
            self.assertNotIn('"tok"', json.dumps(leaked))
            self.assertEqual(fn(200, json.dumps({"access_token": "a.b.c"}), self.ctx)["result"], "fail")


class RedactionTests(unittest.TestCase):
    def test_redactor_replaces_and_flags(self):
        r = h.Redactor()
        r.register("supersecret")
        self.assertEqual(r.guard('{"a":"ok"}'), '{"a":"ok"}')
        self.assertFalse(r.violation)
        line = r.guard('{"a":"xx supersecret yy"}')
        self.assertNotIn("supersecret", line)
        self.assertIn("<redacted>", line)
        self.assertTrue(r.violation)

    def test_redactor_catches_json_escaped(self):
        r = h.Redactor()
        r.register(PASSWORD)
        line = r.guard(json.dumps({"x": PASSWORD}))
        self.assertNotIn(json.dumps(PASSWORD)[1:-1], line)
        self.assertTrue(r.violation)

    def test_sensitive_value_repr(self):
        s = h.SensitiveValue("hunter2")
        self.assertEqual(repr(s), "<redacted>")
        self.assertEqual(str(s), "<redacted>")
        self.assertEqual(f"{s}", "<redacted>")
        self.assertEqual(s.reveal(), "hunter2")

    def test_runner_emit_guard_flags_summary(self):
        r, out, *_ = make_runner()
        r.redactor.register("leakyvalue123")
        r.emit({"event": "x", "v": "leakyvalue123"})
        self.assertNotIn("leakyvalue123", out.getvalue())
        self.assertTrue(r.redactor.violation)


class UrlGuardTests(unittest.TestCase):
    def test_check_url(self):
        self.assertEqual(h.check_url(f"http://127.0.0.1:{PORT}/x", PORT), f"http://127.0.0.1:{PORT}/x")
        for bad in (f"http://localhost:{PORT}/x", f"https://127.0.0.1:{PORT}/x", f"http://127.0.0.1:{PORT + 1}/x",
                    "http://axiom.axiom-phase0-test.svc.cluster.local:8084/oauth/token",
                    f"http://127.0.0.1:{PORT}@evil.example/x", f"http://127.0.0.1:{PORT}", "http://evil.example/"):
            with self.assertRaises(h.HarnessError, msg=bad):
                h.check_url(bad, PORT)
        with self.assertRaises(h.HarnessError):
            h.base_url(8084)

    def test_make_url_rejects_absolute(self):
        self.assertEqual(h.make_url(PORT, "/oauth/token"), f"http://127.0.0.1:{PORT}/oauth/token")
        for bad in ("http://evil.example/token", h.EXPECTED_ISSUER + "/oauth/token", "//evil.example/x",
                    "oauth/token", "/a/../b"):
            with self.assertRaises(h.HarnessError, msg=bad):
                h.make_url(PORT, bad)

    def test_runner_never_follows_discovery_urls(self):
        r, out, cmd, popen, server = make_runner()
        self.assertEqual(r.run(), 0)
        self.assertFalse(any("evil" in p for _m, p in server.calls))
        self.assertIn(("POST", "/oauth/token"), server.calls)

    def test_no_redirect_and_no_proxy(self):
        handler = h._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "http://evil.example/"))
        with mock.patch.dict(h.urllib.request.os.environ, {"http_proxy": "http://proxy.example:3128",
                                                           "HTTP_PROXY": "http://proxy.example:3128"}):
            opener = h.build_opener()
        # An empty ProxyHandler suppresses build_opener's default env-proxy handler.
        proxied = [x for x in opener.handlers if isinstance(x, h.urllib.request.ProxyHandler) and x.proxies]
        self.assertEqual(proxied, [])
        self.assertTrue(any(isinstance(x, h._NoRedirect) for x in opener.handlers))

    def test_default_http_reads_error_body(self):
        err = h.urllib.error.HTTPError(f"http://127.0.0.1:{PORT}/x", 400, "Bad", {}, io.BytesIO(b'{"error":"e"}'))
        opener = mock.Mock()
        opener.open.side_effect = err
        self.assertEqual(h.default_http("GET", f"http://127.0.0.1:{PORT}/x", {}, None, 1, _opener=opener),
                         (400, b'{"error":"e"}'))


class PortTests(unittest.TestCase):
    def test_choose_port_retries_then_succeeds(self):
        socks = []

        class S:
            def __init__(self, *a):
                self.closed = False
                socks.append(self)

            def bind(self, addr):
                self.addr = addr
                if len(socks) < 3:
                    raise OSError("in use")

            def close(self):
                self.closed = True

        port = h.choose_port(rng=lambda n: 7, socket_factory=S)
        self.assertEqual(port, 41007)
        self.assertEqual(len(socks), 3)
        self.assertTrue(all(s.closed for s in socks))
        self.assertEqual(socks[0].addr, ("127.0.0.1", 41007))

    def test_choose_port_gives_up(self):
        class S:
            def __init__(self, *a): pass
            def bind(self, addr): raise OSError()
            def close(self): pass

        calls = []
        self.assertIsNone(h.choose_port(rng=lambda n: calls.append(n) or 1, socket_factory=S))
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[0], 8000)

    def test_choose_port_real_localhost_bind(self):
        port = h.choose_port()
        self.assertTrue(port is None or 41000 <= port < 49000)


class VerificationFailClosedTests(unittest.TestCase):
    def assert_aborted_before_writes(self, runner, out, server, popen=None, expect_popen=True):
        code = runner.run()
        self.assertEqual(code, 2)
        evs = events(out)
        self.assertTrue(evs[-1]["aborted"])
        self.assertEqual(admin_writes(server), [])
        self.assertEqual(evs[-1]["skipped"], 5)
        if popen is not None and not expect_popen:
            self.assertEqual(popen.calls, [])
        return evs

    def run_cmd_case(self, **over):
        r, out, cmd, popen, server = make_runner(cmd=FakeCmd(**over))
        evs = self.assert_aborted_before_writes(r, out, server, popen, expect_popen=False)
        self.assertEqual(server.calls, [])
        return evs, cmd

    def test_v1_context_missing(self):
        self.run_cmd_case(**{"V-1": FakeCompleted(1, "", "error: context not found")})

    def test_v2_bad_namespace(self):
        bad_label = json.loads(good_ns())
        bad_label["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "baseline"
        for out in (FakeCompleted(0, json.dumps(bad_label)), FakeCompleted(1, ""), FakeCompleted(0, "garbage"),
                    FakeCompleted(0, json.dumps({"metadata": {"name": h.NAMESPACE,
                                                              "labels": {"pod-security.kubernetes.io/enforce":
                                                                         "restricted"}}}))):
            self.run_cmd_case(**{"V-2": out})

    def test_v3_bad_release(self):
        two = json.loads(good_helm()) * 2
        wrong_chart = [dict(json.loads(good_helm())[0], chart="axiom-0.1.2")]
        failed = [dict(json.loads(good_helm())[0], status="failed")]
        for doc in (two, wrong_chart, failed, [], {"x": 1}):
            self.run_cmd_case(**{"V-3": FakeCompleted(0, json.dumps(doc))})

    def test_v4_bad_pod(self):
        base = json.loads(good_pods())
        not_ready = json.loads(good_pods())
        not_ready["items"][0]["status"]["conditions"][0]["status"] = "False"
        wrong_digest = json.loads(good_pods())
        wrong_digest["items"][0]["status"]["containerStatuses"][0]["imageID"] = "x@sha256:" + "0" * 64
        two = {"items": base["items"] * 2}
        no_server = json.loads(good_pods())
        no_server["items"][0]["status"]["containerStatuses"][0]["name"] = "sidecar"
        for doc in (not_ready, wrong_digest, two, {"items": []}, no_server):
            self.run_cmd_case(**{"V-4": FakeCompleted(0, json.dumps(doc))})

    def test_v5_bad_secret(self):
        older = f"{h.NAMESPACE}\n2026-09-30T00:00:00Z\naxiom.bootstrap.admin-password\n"
        wrong_ns = f"axiom\n{SECRET_TS}\naxiom.bootstrap.admin-password\n"
        no_key = f"{h.NAMESPACE}\n{SECRET_TS}\naxiom.db.password\n"
        for meta in (older, wrong_ns, no_key, ""):
            self.run_cmd_case(**{"V-5": FakeCompleted(0, meta)})
        for val in (FakeCompleted(0, "!!notbase64!!"), FakeCompleted(0, ""), FakeCompleted(1, "")):
            evs, _ = self.run_cmd_case(**{"V-5v": val})
            self.assertFalse(any(e.get("step") == "V-6" for e in evs))

    def test_v5_value_never_printed_and_argv_not_logged(self):
        r, out, cmd, popen, server = make_runner()
        self.assertEqual(r.run(), 0)
        text = out.getvalue()
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn(json.dumps(PASSWORD)[1:-1], text)
        self.assertNotIn(base64.b64encode(PASSWORD.encode()).decode(), text)
        self.assertNotIn("jsonpath=", text)
        self.assertEqual(repr(r.admin_password), "<redacted>")

    def test_v6_no_port(self):
        r, out, cmd, popen, server = make_runner()
        r.port_chooser = lambda: None
        self.assert_aborted_before_writes(r, out, server, popen, expect_popen=False)
        self.assertEqual(popen.calls, [])

    def http_case(self, key, response):
        now = int(time.time())
        server = FakeServer(now, overrides={key: response})
        r, out, cmd, popen, server = make_runner(server=server, now=now)
        evs = self.assert_aborted_before_writes(r, out, server)
        self.assertTrue(popen.proc.terminated)
        self.assertTrue(any(e["event"] == "port_forward_stop" and e["exited"] for e in evs))
        return evs

    def test_v7_discovery(self):
        k = ("GET", "/.well-known/openid-configuration")
        for doc in ({"issuer": "http://127.0.0.1:41234"},
                    {"issuer": h.EXPECTED_ISSUER + "/"},
                    {}):
            self.http_case(k, (200, json.dumps(doc).encode()))
        self.http_case(k, (302, b""))
        self.http_case(k, (503, b""))

    def test_v7_token_exchange_metadata(self):
        k = ("GET", "/.well-known/oauth-authorization-server")
        for doc in ({"issuer": h.EXPECTED_ISSUER, "grant_types_supported": ["client_credentials"]},
                    {"issuer": h.EXPECTED_ISSUER},
                    {"issuer": "http://127.0.0.1:41234", "grant_types_supported": [h.TOKEN_EXCHANGE_GRANT]}):
            self.http_case(k, (200, json.dumps(doc).encode()))
        self.http_case(k, (404, b""))
        self.http_case(k, (503, b""))

    def test_v8_readiness(self):
        k = ("GET", "/actuator/health/readiness")
        self.http_case(k, (200, b'{"status":"DOWN"}'))
        self.http_case(k, (200, b"UP"))
        self.http_case(k, (503, b'{"status":"OUT_OF_SERVICE"}'))

    def test_v9_login(self):
        k = ("POST", "/auth/login")
        for claims in (admin_claims(roles=["tenant_admin"]), admin_claims(aud=["other"]),
                       admin_claims(tenant_id="acme"), admin_claims(iss="http://127.0.0.1")):
            self.http_case(k, (200, json.dumps({"accessToken": make_jwt(claims)}).encode()))
        self.http_case(k, (401, b'{"error":"unauthorized"}'))
        self.http_case(k, (200, b'{"token":"x"}'))

    def test_v9_accepts_string_aud(self):
        now = int(time.time())
        tok = make_jwt(admin_claims(aud="axiom-api"))
        server = FakeServer(now)
        server.admin_token = tok
        r, out, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 0)

    def test_v10_collision_or_bad_shape(self):
        k = ("GET", "/admin/tenants/meridian/applications")
        self.http_case(k, (200, json.dumps([{"applicationKey": f"{PREFIX}-entry"}]).encode()))
        self.http_case(k, (200, json.dumps({"content": [{"applicationKey": f"{PREFIX}x"}]}).encode()))
        self.http_case(k, (200, b'{"items":[]}'))
        self.http_case(k, (403, b"{}"))

    def test_v10_accepts_plain_list(self):
        now = int(time.time())
        server = FakeServer(now, overrides={("GET", "/admin/tenants/meridian/applications"): (200, b"[]")})
        r, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 0)

    def test_port_forward_never_ready(self):
        popen = FakePopen(port=PORT + 1)
        r, out, cmd, popen, server = make_runner(popen=popen)
        r.pf_ready_timeout = 0.3
        self.assert_aborted_before_writes(r, out, server)
        self.assertEqual(server.calls, [])
        self.assertTrue(popen.proc.terminated)


class FullRunTests(unittest.TestCase):
    def test_happy_path(self):
        r, out, cmd, popen, server = make_runner()
        code = r.run()
        evs = events(out)
        self.assertEqual(code, 0, [e for e in evs if e.get("result") == "fail" or e["event"] == "abort"])
        self.assertEqual(evs[0]["event"], "run_start")
        self.assertEqual(evs[0]["prefix"], PREFIX)
        summary = evs[-1]
        self.assertEqual((summary["passed"], summary["failed"], summary["skipped"]), (5, 0, 0))
        self.assertFalse(summary["aborted"])
        self.assertFalse(summary["redaction_violation"])
        cases = [e for e in evs if e["event"] == "case"]
        self.assertEqual([c["case_id"] for c in cases], list(h.CASE_IDS))
        text = out.getvalue()
        for secret in list(server.secrets.values()) + [server.p1_token, server.p2_token, server.admin_token,
                                                       PASSWORD]:
            self.assertNotIn(secret, text)
        self.assertNotIn("Authorization", text)
        # Every kubectl/helm call carried the fixed context; namespaced calls carry the namespace.
        for argv in cmd.calls + popen.calls:
            if argv[:2] == ["kubectl", "config"]:
                self.assertEqual(argv, ["kubectl", "config", "get-contexts", "docker-desktop"])
                continue
            self.assertIn("docker-desktop", argv)
            self.assertEqual(argv[argv.index("-n") + 1], "axiom-phase0-test")
            self.assertNotIn("axiom", argv)
        self.assertIn("--address", popen.calls[0])
        self.assertTrue(popen.proc.terminated)
        stop = [e for e in evs if e["event"] == "port_forward_stop"]
        self.assertEqual(len(stop), 1)
        self.assertTrue(stop[0]["exited"])

    def test_setup_names(self):
        r, out, cmd, popen, server = make_runner()
        bodies = []
        orig = server.__call__

        def spy(method, url, headers, body, timeout):
            if method == "POST" and "/admin/" in url:
                bodies.append(json.loads(body) if body else None)
            return orig(method, url, headers, body, timeout)

        r.http = spy
        self.assertEqual(r.run(), 0)
        keys = [b["applicationKey"] for b in bodies if b and "applicationKey" in b]
        self.assertEqual(keys, [f"{PREFIX}-entry", f"{PREFIX}-gateway", f"{PREFIX}-sibling"])
        auds = [b["audience"] for b in bodies if b and "applicationKey" in b]
        self.assertEqual(auds, [f"agent:meridian:{PREFIX}-entry", f"{PREFIX}-gateway",
                                f"agent:meridian:{PREFIX}-sibling"])
        clients = [b for b in bodies if b and "clientType" in b]
        self.assertEqual([c["clientId"] for c in clients],
                         [f"{PREFIX}-entry", f"{PREFIX}-gateway-broker", f"{PREFIX}-sibling"])
        for c in clients:
            self.assertEqual(c, {"clientId": c["clientId"], "clientType": "CONFIDENTIAL_SERVICE", "redirectUris": [],
                                 "postLogoutRedirectUris": [], "scopes": ["quickstart:invoke"]})
        wls = [b for b in bodies if b and "workloadRef" in b]
        self.assertEqual([(w["workloadRef"], w["oauthClientId"]) for w in wls],
                         [(f"agent:{PREFIX}-entry:test", f"{PREFIX}-entry"),
                          (f"agent:{PREFIX}-sibling:test", f"{PREFIX}-sibling")])
        broker = [b for b in bodies if b and "gatewayAudience" in b][0]
        self.assertEqual(broker, {"oauthClientId": f"{PREFIX}-gateway-broker", "gatewayAudience": f"{PREFIX}-gateway",
                                  "scopes": ["quickstart:invoke"]})
        route = [b for b in bodies if b and "sourceWorkloadId" in b][0]
        self.assertEqual(route["audience"], f"{PREFIX}-gateway")
        self.assertIsNone(route["destinationWorkloadId"])
        self.assertEqual(route["purpose"], "phase0 H-1 isolated test")

    def test_prefix_format(self):
        p = h.new_prefix()
        self.assertRegex(p, r"^p0h[0-9a-f]{10}$")
        self.assertNotEqual(p, h.new_prefix())

    def test_cleanup_order(self):
        r, out, cmd, popen, server = make_runner()
        self.assertEqual(r.run(), 0)
        steps = [e["step"] for e in events(out) if e["event"] == "cleanup"]
        self.assertEqual(steps, ["revoke_route", "revoke_broker", "revoke_workload:entry", "revoke_workload:sibling",
                                 "disable_client:entry", "disable_client:gateway", "disable_client:sibling",
                                 "disable_application:entry", "disable_application:gateway",
                                 "disable_application:sibling"])
        cleanup_calls = [c for c in server.calls if c[1].endswith("/revoke") or c[0] == "DELETE"]
        self.assertEqual(cleanup_calls[0], ("POST", f"/admin/tenants/meridian/agent-exchange/routes/{ROUTE_ID}/revoke"))
        self.assertTrue(cleanup_calls[-1][0] == "DELETE" and "/clients/" not in cleanup_calls[-1][1])
        # cleanup happens after all token calls
        last_token = max(i for i, c in enumerate(server.calls) if c[1] == "/oauth/token")
        first_cleanup = server.calls.index(cleanup_calls[0])
        self.assertGreater(first_cleanup, last_token)

    def test_cleanup_runs_after_setup_abort(self):
        now = int(time.time())
        server = FakeServer(now, overrides={("POST", "/admin/tenants/meridian/agent-exchange/routes"):
                                            (400, b'{"error":"bad_route"}')})
        r, out, cmd, popen, server = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 2)
        evs = events(out)
        steps = [e["step"] for e in evs if e["event"] == "cleanup"]
        self.assertEqual(steps, ["revoke_broker", "revoke_workload:entry", "revoke_workload:sibling",
                                 "disable_client:entry", "disable_client:gateway", "disable_client:sibling",
                                 "disable_application:entry", "disable_application:gateway",
                                 "disable_application:sibling"])
        self.assertNotIn(("POST", "/oauth/token"), server.calls)
        self.assertEqual(evs[-1]["skipped"], 5)
        self.assertTrue(evs[-1]["aborted"])
        self.assertTrue(popen.proc.terminated)

    def test_cleanup_failure_does_not_change_results(self):
        now = int(time.time())
        server = FakeServer(now, overrides={("DELETE", "/admin/tenants/meridian/applications/app-0001"):
                                            (500, b'{"error":"boom"}')})
        r, out, *_ = make_runner(server=server, now=now)
        # Case results are unchanged; the exit code still flags the incomplete cleanup.
        self.assertEqual(r.run(), 2)
        evs = events(out)
        bad = [e for e in evs if e["event"] == "cleanup" and not e["ok"]]
        self.assertEqual(len(bad), 1)
        self.assertEqual(evs[-1]["passed"], 5)
        self.assertFalse(evs[-1]["aborted"])
        self.assertFalse(evs[-1]["cleanup_complete"])

    def test_p1_failure_skips_rest(self):
        now = int(time.time())
        server = FakeServer(now)
        server.p1_token = make_jwt(p1_claims(now, sid="s1"))
        r, out, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 1)
        evs = events(out)
        res = {e["case_id"]: e["result"] for e in evs if e["event"] == "case"}
        self.assertEqual(res, {"H1-P1": "fail", "H1-P2": "skipped", "H1-N1": "skipped", "H1-N2": "skipped",
                               "H1-N3": "skipped"})
        self.assertFalse(evs[-1]["aborted"])

    def test_case_mismatch_exit_1(self):
        now = int(time.time())
        server = FakeServer(now)
        orig = server.token

        def token(headers, body):
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if form.get("scope", "").count(" "):
                return 200, json.dumps({"access_token": server.p2_token}).encode()
            return orig(headers, body)

        server.token = token
        r, out, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 1)
        evs = events(out)
        res = {e["case_id"]: e["result"] for e in evs if e["event"] == "case"}
        self.assertEqual(res["H1-N3"], "fail")
        self.assertEqual(evs[-1]["passed"], 4)
        self.assertNotIn(server.p2_token, out.getvalue())

    def test_5xx_in_case_aborts(self):
        now = int(time.time())
        server = FakeServer(now)
        orig = server.token

        def token(headers, body):
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if form.get("audience", "").startswith("agent:"):
                return 500, b'{"error":"server_error"}'
            return orig(headers, body)

        server.token = token
        r, out, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 2)
        evs = events(out)
        res = {e["case_id"]: e["result"] for e in evs if e["event"] == "case"}
        self.assertEqual(res, {"H1-P1": "pass", "H1-P2": "pass", "H1-N1": "fail", "H1-N2": "skipped",
                               "H1-N3": "skipped"})
        self.assertTrue(any(e["event"] == "cleanup" for e in evs))

    def test_port_forward_loss_aborts(self):
        popen = FakePopen(die_after_start=True)
        r, out, cmd, popen, server = make_runner(popen=popen)
        self.assertEqual(r.run(), 2)
        self.assertEqual(admin_writes(server), [])
        self.assertTrue(events(out)[-1]["aborted"])


class ReviewHardeningTests(unittest.TestCase):
    """Fixes from the isolation/redaction/rollback review."""

    def _token_override(self, server, on_exchange):
        def handler(headers, body):
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if form.get("grant_type") == h.TOKEN_EXCHANGE_GRANT:
                result = on_exchange(form)
                if result is not None:
                    return result
            return server.token(headers, body)
        server.overrides[("POST", "/oauth/token")] = handler

    def test_redaction_violation_forces_exit_2(self):
        now = int(time.time())
        server = FakeServer(now)
        self._token_override(server, lambda form: (400, json.dumps(
            {"error": "invalid_target", "error_description": "echo " + PASSWORD}).encode())
            if form["audience"].startswith("agent:") else None)
        r, out, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 2)
        text = out.getvalue()
        self.assertNotIn(PASSWORD, text)
        self.assertTrue(events(out)[-1]["redaction_violation"])

    def test_unexpected_exception_in_cleanup_does_not_stop_remaining_steps(self):
        now = int(time.time())
        def explode(headers, body):
            raise ValueError("boom with data")
        server = FakeServer(now, overrides={("DELETE", "/admin/tenants/meridian/applications/app-0001/clients/client-0004"):
                                            explode})
        r, out, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 2)
        evs = [e for e in events(out) if e["event"] == "cleanup"]
        failed = [e for e in evs if not e["ok"]]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["reason"], "unexpected ValueError")
        self.assertNotIn("boom with data", out.getvalue())
        self.assertTrue(any(e["step"] == "disable_application:sibling" and e["ok"] for e in evs))

    def test_unsafe_server_id_is_never_used_in_a_path(self):
        now = int(time.time())
        server = FakeServer(now, overrides={("POST", "/admin/tenants/meridian/agent-exchange/brokers"):
                                            (201, json.dumps({"id": "../x?y"}).encode())})
        r, out, *_ = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 2)
        self.assertFalse(any("../x" in path or "x?y" in path for _m, path in server.calls))
        bad = [e for e in events(out) if e["event"] == "cleanup" and not e["ok"]]
        self.assertEqual([e["step"] for e in bad], ["revoke_broker"])
        self.assertEqual(bad[0]["reason"], "unsafe server id")

    def test_keyboard_interrupt_during_cases_still_cleans_up(self):
        now = int(time.time())
        server = FakeServer(now)
        def interrupt(form):
            raise KeyboardInterrupt
        self._token_override(server, interrupt)
        r, out, cmd, popen, server = make_runner(server=server, now=now)
        self.assertEqual(r.run(), 2)
        evs = events(out)
        self.assertEqual(evs[-1]["abort_reason"], "interrupted")
        cleanup = [e for e in evs if e["event"] == "cleanup"]
        self.assertTrue(cleanup and all(e["ok"] for e in cleanup))
        self.assertTrue(popen.proc.terminated)

    def test_port_forward_lost_mid_run_restarts_once_for_cleanup(self):
        now = int(time.time())
        popen = FakePopen()
        server = FakeServer(now)
        def lose_forward(form):
            popen.proc.returncode = 1
            raise urllib.error.URLError("connection refused")
        self._token_override(server, lose_forward)
        r, out, cmd, popen, server = make_runner(popen=popen, server=server, now=now)
        self.assertEqual(r.run(), 2)
        evs = events(out)
        self.assertEqual(len(popen.calls), 2)
        self.assertTrue(any(e["event"] == "port_forward_restart" and e["ok"] for e in evs))
        cleanup = [e for e in evs if e["event"] == "cleanup"]
        self.assertTrue(cleanup and all(e["ok"] for e in cleanup))
        self.assertTrue(popen.proc.terminated)

    def test_stuck_port_forward_is_reported_and_exits_2(self):
        class StuckProc(FakeProc):
            def terminate(self):
                self.terminated = True
            def kill(self):
                pass
            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("kubectl", timeout)
        r, out, *_ = make_runner()
        r.pf = StuckProc()
        r.stop_port_forward()
        ev = events(out)[-1]
        self.assertEqual((ev["exited"], ev["killed"]), (False, True))
        self.assertTrue(r.pf_leaked)

    def test_default_popen_new_session_and_no_proxy_env(self):
        with mock.patch.dict(h.os.environ, {"HTTPS_PROXY": "http://proxy.invalid:1", "KUBECONFIG": "/k"}), \
                mock.patch.object(subprocess, "Popen") as popen_mock, mock.patch.object(subprocess, "run") as run_mock:
            h.default_popen(["kubectl", "port-forward"])
            h.default_run_cmd(["kubectl", "get"])
        kw = popen_mock.call_args.kwargs
        self.assertTrue(kw["start_new_session"])
        self.assertFalse(kw["shell"])
        self.assertNotIn("HTTPS_PROXY", kw["env"])
        self.assertEqual(kw["env"].get("KUBECONFIG"), "/k")
        self.assertNotIn("HTTPS_PROXY", run_mock.call_args.kwargs["env"])

    def test_command_builder_rejects_cluster_and_identity_overrides(self):
        for extra in (["--server=https://x"], ["-s", "https://x"], ["--as", "system:admin"], ["--token=t"],
                      ["--user", "u"], ["--cluster=c"], ["--insecure-skip-tls-verify"]):
            with self.assertRaises(h.HarnessError):
                h.build_command("kubectl", "get", "pods", *extra)

    def test_redactor_covers_url_encoded_forms(self):
        red = h.Redactor()
        red.register("p@ss w/rd")
        line = red.guard("a=p%40ss+w%2Frd b=p%40ss%20w%2Frd")
        self.assertNotIn("p%40ss", line)
        self.assertTrue(red.violation)

    def test_signal_handlers_installed_for_execute(self):
        seen = {}
        def factory(out):
            seen["term"] = h.signal.getsignal(h.signal.SIGTERM)
            runner = mock.Mock()
            runner.run.return_value = 0
            return runner
        prev = {sig: h.signal.getsignal(sig) for sig in (h.signal.SIGTERM, h.signal.SIGHUP)}
        try:
            self.assertEqual(h.main(["--execute"], out=io.StringIO(), runner_factory=factory), 0)
            with self.assertRaises(KeyboardInterrupt):
                seen["term"](h.signal.SIGTERM, None)
        finally:
            for sig, handler in prev.items():
                h.signal.signal(sig, handler)


class PlanModeTests(unittest.TestCase):
    def test_plan_mode_makes_no_calls(self):
        out = io.StringIO()
        factory = mock.Mock()
        boom = mock.Mock(side_effect=AssertionError("no process/network allowed"))
        with mock.patch.object(subprocess, "run", boom), mock.patch.object(subprocess, "Popen", boom), \
                mock.patch.object(h.urllib.request, "urlopen", boom), \
                mock.patch.object(h.urllib.request.OpenerDirector, "open", boom), \
                mock.patch.object(h.socket, "socket", boom):
            code = h.main([], out=out, runner_factory=factory)
        self.assertEqual(code, 0)
        factory.assert_not_called()
        boom.assert_not_called()
        evs = events(out)
        kinds = {e["event"] for e in evs}
        self.assertTrue({"plan", "plan_verify", "plan_identities", "plan_case", "plan_cleanup"} <= kinds)
        self.assertEqual([e["case_id"] for e in evs if e["event"] == "plan_case"], list(h.CASE_IDS))
        self.assertEqual(len([e for e in evs if e["event"] == "plan_verify"]), 11)

    def test_execute_uses_runner(self):
        out = io.StringIO()
        runner = mock.Mock()
        runner.run.return_value = 0
        factory = mock.Mock(return_value=runner)
        self.assertEqual(h.main(["--execute"], out=out, runner_factory=factory), 0)
        factory.assert_called_once()

    def test_refuses_old_python(self):
        with mock.patch.object(h.sys, "version_info", (3, 12, 0)):
            err = io.StringIO()
            with mock.patch.object(h.sys, "stderr", err):
                self.assertEqual(h.main([], out=io.StringIO()), 2)


if __name__ == "__main__":
    unittest.main()
