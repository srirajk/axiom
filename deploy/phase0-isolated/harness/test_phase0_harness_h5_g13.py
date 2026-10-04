"""Mock-only G-13 tests; no real subprocess, socket, cluster or network."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

import phase0_harness_h5_g13 as g13
from test_phase0_harness import FakeCmd, PORT, PREFIX
from test_phase0_harness_h2 import NOW, SeqPopen, resp
from test_phase0_harness_h4 import FakeH4Server


class FakeG13Server(FakeH4Server):
    def __init__(self, *, revoke_on_disable=False, reject_disable=False):
        super().__init__()
        self.revoke_on_disable = revoke_on_disable
        self.reject_disable = reject_disable

    def admin(self, method, path, query, body, base):
        if method == "PUT" and path == f"/users/{PREFIX}-user":
            if self.reject_disable:
                return resp(409, {"error": "conflict"})
            assert json.loads(body) == {"isActive": False}
            if self.revoke_on_disable:
                root = self.hop_claims["P1"]["sid"]
                for session in self.iam_sessions:
                    if session["id"] == root:
                        session["status"] = "REVOKED"
            return resp(200, {"id": f"{PREFIX}-user", "isActive": False})
        return super().admin(method, path, query, body, base)


def run_full(server=None):
    server = server or FakeG13Server()
    out = io.StringIO()
    runner = g13.G13Runner(run_cmd=FakeCmd(), popen=SeqPopen(), http=server, out=out,
                           now=lambda: NOW, prefix=PREFIX, port_chooser=lambda: PORT,
                           pf_ready_timeout=2.0)
    code = runner.run()
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    cases = {e["case_id"]: e for e in events if e.get("event") == "h5_case"}
    summary = next(e for e in events if e.get("event") == "h5_summary")
    return code, cases, summary, events, out.getvalue()


class G13Tests(unittest.TestCase):
    def test_plan_only(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(g13.main(["--package", "h5-g13"]), 0)
        self.assertIn('"namespace": "axiom-phase0-test"', out.getvalue())

    def test_disable_does_not_revoke_classified(self):
        code, cases, summary, _events, text = run_full()
        self.assertEqual(code, 0, [(k, v["mismatches"]) for k, v in cases.items() if v["result"] != "pass"])
        self.assertEqual(summary["passed"], 21)
        self.assertTrue(cases[g13.EXTRA[1]]["observed"]["root_session_active"])
        self.assertTrue(cases[g13.EXTRA[2]]["observed"]["active"])
        self.assertTrue(cases[g13.EXTRA[3]]["observed"]["active"])
        self.assertTrue(cases[g13.EXTRA[4]]["observed"]["exchange_issued"])
        self.assertTrue(summary["cleanup_complete"])
        self.assertNotIn("Bearer ", text)

    def test_immediate_revocation_is_valid_alternate_observation(self):
        code, cases, summary, _events, _text = run_full(FakeG13Server(revoke_on_disable=True))
        self.assertEqual(code, 0, [(k, v["mismatches"]) for k, v in cases.items() if v["result"] != "pass"])
        self.assertFalse(cases[g13.EXTRA[1]]["observed"]["root_session_active"])
        self.assertFalse(cases[g13.EXTRA[2]]["observed"]["active"])
        self.assertFalse(cases[g13.EXTRA[3]]["observed"]["active"])
        self.assertFalse(cases[g13.EXTRA[4]]["observed"]["exchange_issued"])
        self.assertTrue(summary["cleanup_complete"])

    def test_disable_failure_skips_all_followups(self):
        code, cases, summary, _events, _text = run_full(FakeG13Server(reject_disable=True))
        self.assertEqual(code, 1)
        self.assertEqual(cases[g13.EXTRA[0]]["result"], "fail")
        self.assertTrue(all(cases[cid]["result"] == "skipped" for cid in g13.EXTRA[1:]))
        self.assertTrue(summary["cleanup_complete"])


if __name__ == "__main__":
    unittest.main()
