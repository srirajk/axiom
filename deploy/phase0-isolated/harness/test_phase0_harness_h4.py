"""Fully mocked H-4 tests; no subprocess, socket, cluster or network access."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

import phase0_harness_h4 as h4
from test_phase0_harness import FakeCmd, PORT, PREFIX
from test_phase0_harness_h2 import NOW, SeqPopen, resp
from test_phase0_harness_h3 import FakeH3Server


class FakeH4Server(FakeH3Server):
    def __init__(self):
        super().__init__()
        self.ignore_root_revoke = False
        self.allow_exchange_after_revoke = False
        self.keep_tokens_active_after_revoke = False

    def redeem(self, headers, form):
        result = super().redeem(headers, form)
        if self.hop_claims.get("P1") and self.iam_sessions:
            self.iam_sessions[-1]["id"] = self.hop_claims["P1"]["sid"]
        return result

    @property
    def root_revoked(self):
        p1 = self.hop_claims.get("P1")
        return bool(p1 and any(s["id"] == p1["sid"] and s["status"] == "REVOKED"
                               for s in self.iam_sessions))

    def introspect(self, headers, body):
        if self.root_revoked and not self.keep_tokens_active_after_revoke:
            # Preserve the fake's request and authentication assertions. A genuine descendant
            # is inactive after root revocation; a tampered token was already inactive.
            import urllib.parse
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if form.get("token") in self.tokens and headers.get("Authorization", "").startswith("Basic "):
                return resp(200, {"active": False})
        return super().introspect(headers, body)

    def exchange(self, headers, form):
        if self.root_revoked and not self.allow_exchange_after_revoke \
                and form.get("subject_token") in self.tokens:
            return resp(400, {"error": "invalid_grant"})
        return super().exchange(headers, form)


def run_full(server=None):
    server = server or FakeH4Server()
    out = io.StringIO()
    runner = h4.H4Runner(run_cmd=FakeCmd(), popen=SeqPopen(), http=server, out=out,
                         now=lambda: NOW, prefix=PREFIX, port_chooser=lambda: PORT, pf_ready_timeout=2.0)
    code = runner.run()
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    cases = {e["case_id"]: e for e in events if e.get("event") == "h4_case"}
    summary = next(e for e in events if e.get("event") == "h4_summary")
    return code, cases, summary, server, out.getvalue()


class H4Tests(unittest.TestCase):
    def test_pinned_h3(self):
        self.assertIs(h4.load_h3(), h4.h3)
        self.assertEqual(h4.h3._file_digest(h4.H3_PATH), h4.H3_SHA256)

    def test_plan_has_no_runner_or_network(self):
        self.assertEqual(len(h4.EXTRA_ORDER), 8)
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(h4.main(["--package", "h4"]), 0)
        self.assertIn('"case_id": "H4-R1"', out.getvalue())
        self.assertIn('"prefix_template": "p4h + secrets.token_hex(5)"', out.getvalue())

    def test_happy_path_revokes_root_and_cascades(self):
        code, cases, summary, server, text = run_full()
        self.assertEqual(code, 0, [(k, v["mismatches"]) for k, v in cases.items() if v["result"] != "pass"])
        self.assertEqual(len(cases), 24)
        self.assertTrue(all(v["result"] == "pass" for v in cases.values()))
        self.assertEqual((summary["passed"], summary["failed"], summary["skipped"]), (24, 0, 0))
        self.assertTrue(summary["cleanup_complete"])
        self.assertFalse(summary["port_forward_leaked"] or summary["redaction_violation"])
        self.assertTrue(server.root_revoked)
        self.assertNotIn(server.hop_claims["P1"]["sid"], text)

    def test_revocation_does_not_imply_inactivity_without_proof(self):
        server = FakeH4Server()
        server.keep_tokens_active_after_revoke = True
        code, cases, summary, _server, _text = run_full(server)
        self.assertEqual(code, 1)
        self.assertEqual(cases["H4-R1"]["result"], "pass")
        self.assertTrue(any(cases[f"H4-I{i}"]["result"] == "fail" for i in range(1, 7)))
        self.assertTrue(summary["cleanup_complete"])

    def test_exchange_allowed_after_revoke_fails(self):
        server = FakeH4Server()
        server.allow_exchange_after_revoke = True
        code, cases, _summary, _server, _text = run_full(server)
        self.assertEqual(code, 1)
        self.assertEqual(cases["H4-X1"]["result"], "fail")


if __name__ == "__main__":
    unittest.main()
