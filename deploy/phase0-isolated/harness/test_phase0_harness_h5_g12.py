"""Mock-only G-12 tests; no real subprocess, socket, cluster or network."""

from __future__ import annotations

import io
import json
import unittest
import urllib.parse
from contextlib import redirect_stdout

import phase0_harness_h5_g12 as g12
from test_phase0_harness import FakeCmd, PORT, PREFIX
from test_phase0_harness_h2 import NOW, SeqPopen, resp
from test_phase0_harness_h3 import FakeH3Server


class FakeG12Server(FakeH3Server):
    def __init__(self, *, ignore_revoke=False, keep_active=False, allow_exchange=False):
        super().__init__()
        self.ignore_r4_revoke = ignore_revoke
        self.keep_r4_active = keep_active
        self.allow_after_revoke = allow_exchange
        self.r4_revoked = False

    def admin(self, method, path, query, body, base):
        if (method == "POST" and path.endswith("/revoke") and self.routes
                and path == f"{base}/agent-exchange/routes/{self.routes[-1]}/revoke"):
            if not self.ignore_r4_revoke:
                self.r4_revoked = True
                return resp(200, {"id": self.routes[-1], "status": "REVOKED"})
            return resp(409, {"error": "conflict"})
        return super().admin(method, path, query, body, base)

    def introspect(self, headers, body):
        form = dict(urllib.parse.parse_qsl(body.decode()))
        if (self.r4_revoked and not self.keep_r4_active
                and self.tokens.get(form.get("token")) == "P6"):
            return resp(200, {"active": False})
        return super().introspect(headers, body)

    def exchange(self, headers, form):
        if (self.r4_revoked and not self.allow_after_revoke
                and self.tokens.get(form.get("subject_token")) == "P5"
                and form.get("audience") == f"tool:meridian:{PREFIX}-tool"):
            return resp(400, {"error": "invalid_target"})
        return super().exchange(headers, form)


def run_full(server=None):
    server = server or FakeG12Server()
    out = io.StringIO()
    runner = g12.G12Runner(run_cmd=FakeCmd(), popen=SeqPopen(), http=server, out=out,
                           now=lambda: NOW, prefix=PREFIX, port_chooser=lambda: PORT,
                           pf_ready_timeout=2.0)
    code = runner.run()
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    cases = {e["case_id"]: e for e in events if e.get("event") == "h5_case"}
    summary = next(e for e in events if e.get("event") == "h5_summary")
    return code, cases, summary, events, out.getvalue()


class G12Tests(unittest.TestCase):
    def test_plan_only(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(g12.main(["--package", "h5-g12"]), 0)
        self.assertIn('"namespace": "axiom-phase0-test"', out.getvalue())

    def test_route_revoke_reaches_introspection_and_exchange(self):
        code, cases, summary, events, text = run_full()
        self.assertEqual(code, 0, [(k, v["mismatches"]) for k, v in cases.items() if v["result"] != "pass"])
        self.assertEqual(summary["passed"], 20)
        self.assertTrue(summary["cleanup_complete"])
        self.assertEqual(cases[g12.EXTRA[1]]["observed"]["active"], False)
        self.assertEqual(cases[g12.EXTRA[2]]["observed"]["active"], True)
        self.assertFalse(any(e.get("step") == "revoke_route:R4" for e in events))
        self.assertNotIn("Bearer ", text)

    def test_revoke_failure_fails_and_cleanup_attempts_r4(self):
        code, cases, summary, events, _text = run_full(FakeG12Server(ignore_revoke=True))
        self.assertEqual(code, 2)
        self.assertEqual(cases[g12.EXTRA[0]]["result"], "fail")
        self.assertTrue(any(e.get("step") == "revoke_route:R4" for e in events))
        self.assertFalse(summary["cleanup_complete"])

    def test_stale_active_token_detected(self):
        code, cases, summary, _events, _text = run_full(FakeG12Server(keep_active=True))
        self.assertEqual(code, 1)
        self.assertEqual(cases[g12.EXTRA[1]]["result"], "fail")
        self.assertTrue(summary["cleanup_complete"])

    def test_exchange_still_allowed_detected(self):
        code, cases, summary, _events, _text = run_full(FakeG12Server(allow_exchange=True))
        self.assertEqual(code, 1)
        self.assertEqual(cases[g12.EXTRA[3]]["result"], "fail")
        self.assertTrue(summary["cleanup_complete"])


if __name__ == "__main__":
    unittest.main()
