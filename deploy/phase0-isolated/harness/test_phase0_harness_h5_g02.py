"""Fully mocked H-5/G-02 tests; no real subprocess, socket, cluster or network."""

from __future__ import annotations

import io
import json
import unittest
import urllib.parse
from contextlib import redirect_stdout

import phase0_harness_h5_g02 as g02
from test_phase0_harness import FakeCmd, PORT, PREFIX
from test_phase0_harness_h2 import NOW, SeqPopen, resp
from test_phase0_harness_h4 import FakeH4Server


class FakeG02Server(FakeH4Server):
    def __init__(self, *, reject=False, missing_id=False):
        super().__init__()
        self.reject_extra = reject
        self.missing_extra_id = missing_id

    def __call__(self, method, url, headers, body, timeout):
        path = urllib.parse.urlsplit(url).path
        if method == "POST" and path.endswith("/ciam/agent-workloads") and body:
            doc = json.loads(body)
            if doc.get("oauthClientId") == f"{PREFIX}-gateway-broker":
                self.requests.append({"method": method, "path": path, "headers": dict(headers), "body": body})
                if self.reject_extra:
                    return resp(409, {"error": "conflict"})
                if self.missing_extra_id:
                    return resp(201, {"status": "ACTIVE"})
                return resp(201, {"id": "workload-extra", "status": "ACTIVE"})
        return super().__call__(method, url, headers, body, timeout)


def run_full(server=None):
    server = server or FakeG02Server()
    out = io.StringIO()
    runner = g02.G02Runner(run_cmd=FakeCmd(), popen=SeqPopen(), http=server, out=out,
                           now=lambda: NOW, prefix=PREFIX, port_chooser=lambda: PORT, pf_ready_timeout=2.0)
    code = runner.run()
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    cases = {e["case_id"]: e for e in events if e.get("event") == "h5_case"}
    summary = next(e for e in events if e.get("event") == "h5_summary")
    return code, cases, summary, events, out.getvalue()


class G02Tests(unittest.TestCase):
    def test_plan_only(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(g02.main(["--package", "h5-g02"]), 0)
        self.assertIn('"namespace": "axiom-phase0-test"', out.getvalue())

    def test_gap_present_classified_and_extra_workload_cleaned(self):
        code, cases, summary, events, text = run_full()
        self.assertEqual(code, 0, cases[g02.CASE_ID]["mismatches"])
        self.assertEqual(summary["passed"], 25)
        self.assertEqual(cases[g02.CASE_ID]["observed"]["classification"],
                         "gap_present_broker_then_workload_allowed")
        self.assertTrue(any(e.get("step") == "revoke_workload:broker_after" and e.get("ok")
                            for e in events if e["event"] == "h5_cleanup"))
        self.assertNotIn("Bearer ", text)

    def test_rejection_is_valid_observation_without_extra_cleanup(self):
        code, cases, summary, events, _text = run_full(FakeG02Server(reject=True))
        self.assertEqual(code, 0)
        self.assertEqual(summary["passed"], 25)
        self.assertEqual(cases[g02.CASE_ID]["observed"]["classification"], "registration_rejected")
        self.assertFalse(any(e.get("step") == "revoke_workload:broker_after" for e in events))

    def test_created_object_without_id_aborts_cleanly(self):
        code, cases, summary, _events, _text = run_full(FakeG02Server(missing_id=True))
        self.assertEqual(code, 2)
        self.assertEqual(cases[g02.CASE_ID]["result"], "fail")
        self.assertFalse(summary["cleanup_complete"])

    def test_failed_prerequisite_skips_characterization(self):
        server = FakeG02Server()
        server.keep_tokens_active_after_revoke = True
        code, cases, _summary, _events, _text = run_full(server)
        self.assertEqual(code, 1)
        self.assertEqual(cases[g02.CASE_ID]["result"], "skipped")


if __name__ == "__main__":
    unittest.main()
