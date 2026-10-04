"""Mock-only G-07 tests: no real subprocess, socket, cluster or network."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

import phase0_harness_h5_g07 as g07
from test_phase0_harness import FakeCmd, PORT, PREFIX, make_jwt
from test_phase0_harness_h2 import NOW, SeqPopen, hop_claims, resp
from test_phase0_harness_h3 import FakeH3Server


class FakeG07Server(FakeH3Server):
    def __init__(self, *, reject=False, bad_authority=False):
        super().__init__()
        self.reject_cross_app = reject
        self.bad_authority = bad_authority

    def exchange(self, headers, form):
        if (self._client(headers.get("Authorization", "")) == f"{PREFIX}-sibling"
                and self.tokens.get(form.get("subject_token")) == "P1"
                and form.get("audience") == f"agent:meridian:{PREFIX}-sibling"):
            if self.reject_cross_app:
                return resp(400, {"error": "invalid_grant"})
            app = next(aid for aid, doc in self.apps.items()
                       if doc.get("applicationKey") == f"{PREFIX}-sibling")
            v = self.vars()
            p1 = self.hop_claims["P1"]
            claims = hop_claims("P2", v, p1["exp"], self._id("sid"))
            claims.update(aud=[form["audience"]], client_id=f"{PREFIX}-sibling",
                          azp=f"{PREFIX}-sibling", subject_sid=p1["sid"],
                          authority_id=f"workforce:{app}:{v['user']}:2",
                          act={"sub": f"agent:{PREFIX}-sibling:test",
                               "client_id": f"{PREFIX}-sibling",
                               "workload_id": self.workloads[f"{PREFIX}-sibling"]})
            if self.bad_authority:
                claims["authority_id"] = "workforce:wrong-app:user:2"
            token = self._sensitive(make_jwt(claims))
            return resp(200, {"access_token": token, "token_type": "Bearer",
                              "issued_token_type": g07.h2.ACCESS_TOKEN_TYPE,
                              "authority_id": claims["authority_id"]})
        return super().exchange(headers, form)


def run_full(server=None):
    server = server or FakeG07Server()
    out = io.StringIO()
    runner = g07.G07Runner(run_cmd=FakeCmd(), popen=SeqPopen(), http=server, out=out,
                           now=lambda: NOW, prefix=PREFIX, port_chooser=lambda: PORT,
                           pf_ready_timeout=2.0)
    code = runner.run()
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    cases = {e["case_id"]: e for e in events if e.get("event") == "h5_case"}
    summary = next(e for e in events if e.get("event") == "h5_summary")
    return code, cases, summary, events, out.getvalue()


class G07Tests(unittest.TestCase):
    def test_plan_only(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(g07.main(["--package", "h5-g07"]), 0)
        self.assertIn('"namespace": "axiom-phase0-test"', out.getvalue())

    def test_gap_present_with_claims_and_cleanup(self):
        code, cases, summary, events, text = run_full()
        self.assertEqual(code, 0, cases[g07.CASE_ID]["mismatches"])
        self.assertEqual(summary["passed"], 17)
        self.assertEqual(cases[g07.CASE_ID]["observed"]["classification"],
                         "gap_present_cross_application_exchange_allowed")
        self.assertTrue(all(cases[g07.CASE_ID]["observed"]["claim_checks"].values()))
        self.assertTrue(any(e.get("step") == "remove_cross_app_membership" and e.get("ok")
                            for e in events if e["event"] == "h5_cleanup"))
        self.assertTrue(summary["cleanup_complete"])
        self.assertNotIn("Bearer ", text)

    def test_rejection_is_valid_observation(self):
        code, cases, summary, _events, _text = run_full(FakeG07Server(reject=True))
        self.assertEqual(code, 0, cases[g07.CASE_ID]["mismatches"])
        self.assertEqual(summary["passed"], 17)
        self.assertEqual(cases[g07.CASE_ID]["observed"]["classification"],
                         "cross_application_exchange_rejected")

    def test_misbound_authority_fails(self):
        code, cases, summary, _events, _text = run_full(FakeG07Server(bad_authority=True))
        self.assertEqual(code, 1)
        self.assertEqual(cases[g07.CASE_ID]["result"], "fail")
        self.assertTrue(summary["cleanup_complete"])

    def test_prerequisite_failure_skips_characterization(self):
        server = FakeG07Server()
        server.inactive_hops.add("P1")
        code, cases, _summary, _events, _text = run_full(server)
        self.assertEqual(code, 1)
        self.assertEqual(cases[g07.CASE_ID]["result"], "skipped")


if __name__ == "__main__":
    unittest.main()
