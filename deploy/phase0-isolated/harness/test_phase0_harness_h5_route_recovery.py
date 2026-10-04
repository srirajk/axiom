"""Mock-only route recovery tests; no real subprocess, socket, cluster or network."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

import phase0_harness_h5_route_recovery as rr
from test_phase0_harness import FakeCmd, PORT, PREFIX, make_jwt
from test_phase0_harness_h2 import NOW, SeqPopen, hop_claims, resp
from test_phase0_harness_h5_g12 import FakeG12Server


class FakeRecoveryServer(FakeG12Server):
    def __init__(self, *, reject_replacement=False):
        super().__init__()
        self.reject_replacement = reject_replacement
        self.recovery_route = None

    def admin(self, method, path, query, body, base):
        if method == "POST" and path == f"{base}/agent-exchange/routes" and self.r4_revoked:
            if self.reject_replacement:
                return resp(409, {"error": "conflict"})
            result = super().admin(method, path, query, body, base)
            self.recovery_route = self.routes[-1]
            return result
        return super().admin(method, path, query, body, base)

    def exchange(self, headers, form):
        if (self.recovery_route and self.tokens.get(form.get("subject_token")) == "P5"
                and form.get("audience") == f"tool:meridian:{PREFIX}-tool"):
            v = self.vars()
            claims = hop_claims("P6", v, self.hop_claims["P5"]["exp"], self._id("sid"))
            claims["authority_id"] = self.recovery_route
            token = self._sensitive(make_jwt(claims))
            self.tokens[token] = "P6R"
            self.hop_claims["P6R"] = claims
            return resp(200, {"access_token": token, "token_type": "Bearer",
                              "issued_token_type": rr.h2.ACCESS_TOKEN_TYPE,
                              "authority_id": self.recovery_route})
        return super().exchange(headers, form)


def run_full(server=None):
    server = server or FakeRecoveryServer()
    out = io.StringIO()
    runner = rr.RouteRecoveryRunner(run_cmd=FakeCmd(), popen=SeqPopen(), http=server, out=out,
                                    now=lambda: NOW, prefix=PREFIX, port_chooser=lambda: PORT,
                                    pf_ready_timeout=2.0)
    code = runner.run()
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    cases = {e["case_id"]: e for e in events if e.get("event") == "h5_case"}
    summary = next(e for e in events if e.get("event") == "h5_summary")
    return code, cases, summary, events, out.getvalue()


class RouteRecoveryTests(unittest.TestCase):
    def test_plan_only(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(rr.main(["--package", "route-recovery"]), 0)
        self.assertIn('"namespace": "axiom-phase0-test"', out.getvalue())

    def test_replacement_new_token_active_old_stays_inactive(self):
        code, cases, summary, events, text = run_full()
        self.assertEqual(code, 0, [(k, v["mismatches"]) for k, v in cases.items() if v["result"] != "pass"])
        self.assertEqual(summary["passed"], 23)
        self.assertFalse(cases[rr.EXTRA[2]]["observed"]["old_active"])
        self.assertTrue(cases[rr.EXTRA[2]]["observed"]["new_active"])
        self.assertTrue(any(e.get("step") == "revoke_replacement_route" and e.get("ok")
                            for e in events if e.get("event") == "h5_cleanup"))
        self.assertTrue(summary["cleanup_complete"])
        self.assertNotIn("Bearer ", text)

    def test_replacement_rejection_does_not_issue_new_token(self):
        code, cases, summary, events, _text = run_full(FakeRecoveryServer(reject_replacement=True))
        self.assertEqual(code, 1)
        self.assertEqual(cases[rr.EXTRA[0]]["result"], "fail")
        self.assertEqual(cases[rr.EXTRA[1]]["result"], "skipped")
        self.assertFalse(any(e.get("step") == "revoke_replacement_route" for e in events))
        self.assertTrue(summary["cleanup_complete"])


if __name__ == "__main__":
    unittest.main()
