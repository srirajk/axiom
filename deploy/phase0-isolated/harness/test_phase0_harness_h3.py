"""Unit tests for phase0_harness_h3 (H-3). Fully mocked: no real subprocess, socket, cluster or network access."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import types
import unittest
import urllib.parse
import urllib.request
from unittest import mock

import phase0_harness as h1
import phase0_harness_h2 as h2
import phase0_harness_h3 as h3
from test_phase0_harness import FakeCmd, PORT, PREFIX, make_jwt
from test_phase0_harness_h2 import NOW, FakeH2Server, SeqPopen, SeqProc, resp

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = {
    "phase0_harness.py": "10ffb18b65e09ffc66439583ae299ee0ac10a7aa724d398e4aedee342aa3eebc",
    "phase0_harness_h2.py": "30b949d2aad7ad6400d905666c8fbd68faae67ff824afbbc359936bc3c855f7d",
}
V = h2.base_vars(PREFIX)
HOP = {f"H3-C{n}": f"P{n}" for n in range(1, 7)}
DROP = object()
CHALLENGE_401 = ('Bearer error="invalid_token", error_description="An error occurred while attempting to decode '
                 'the Jwt: Signed JWT rejected: Invalid signature"')


def events(out: io.StringIO) -> list[dict]:
    return [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]


def cases_of(evs: list[dict]) -> dict:
    return {e["case_id"]: e for e in evs if e["event"] == "h3_case"}


def summary_of(evs: list[dict]) -> dict:
    return [e for e in evs if e["event"] == "h3_summary"][-1]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _set_path(doc: dict, path: str, value) -> None:
    parts = path.split(".")
    cur = doc
    for p in parts[:-1]:
        if not isinstance(cur.get(p), dict):
            cur[p] = {}
        cur = cur[p]
    if value is DROP:
        cur.pop(parts[-1], None)
    elif callable(value):
        cur[parts[-1]] = value(cur.get(parts[-1]))
    else:
        cur[parts[-1]] = value


# ---------------------------------------------------------------------------------------------------------------------
# Fake server: H-2 fake plus introspection, tampered exchange subjects and /api/me/sessions
# ---------------------------------------------------------------------------------------------------------------------

class FakeH3Server(FakeH2Server):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.introspect_mutations: dict = {}     # hop -> {path: value | callable | DROP}
        self.introspection_extra: dict = {}      # extra members on every active response
        self.inactive_hops: set = set()
        self.tampered_active = False
        self.tampered_extra = False
        self.tampered_subject_issues = False
        self.tampered_subject_echo = False
        self.me_control_status = 200
        self.me_tampered_status = 401
        self.me_tampered_challenge = CHALLENGE_401
        self.noauth_status = 401
        self.noauth_active = False
        self.noauth_challenge = "Bearer"
        self.introspections: list = []           # (client_id | None, hop | None)
        self.me_calls: list = []

    def __call__(self, method, url, headers, body, timeout):
        parts = urllib.parse.urlsplit(url)
        key = (method, parts.path)
        if key not in (("POST", "/oauth/introspect"), ("GET", "/api/me/sessions")):
            return super().__call__(method, url, headers, body, timeout)
        if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.port not in self.ports:
            self.bad_urls.append(url)
            raise AssertionError("request to a non-forwarded URL")
        self.port = parts.port
        self.calls.append(key)
        self.requests.append({"method": method, "path": parts.path, "query": parts.query, "headers": dict(headers),
                              "body": body})
        if key in self.overrides:
            r = self.overrides[key]
            out = r(headers, body) if callable(r) else r
            if out is not None:
                return out
        if key[1] == "/oauth/introspect":
            return self.introspect(headers, body)
        return self.me_sessions(headers)

    def _client(self, auth):
        cid, secret = base64.b64decode(auth[6:]).decode().split(":", 1)
        cid, secret = urllib.parse.unquote_plus(cid), urllib.parse.unquote_plus(secret)
        client = self.clients.get(cid)
        return cid if client is not None and client.get("secret") == secret else None

    def introspect(self, headers, body):
        assert headers.get("Accept") == "application/json"
        assert headers.get("Content-Type") == "application/x-www-form-urlencoded"
        form = dict(urllib.parse.parse_qsl(body.decode()))
        assert set(form) == {"token", "token_type_hint"} and form["token_type_hint"] == "access_token"
        self._sensitive(form["token"])
        hop = self.tokens.get(form["token"])
        auth = headers.get("Authorization")
        if auth is None:
            self.introspections.append((None, hop))
            hdrs = [("WWW-Authenticate", self.noauth_challenge)] if self.noauth_challenge else []
            return resp(self.noauth_status, {"active": True} if self.noauth_active else b"", hdrs)
        assert auth.startswith("Basic ")
        cid = self._client(auth)
        if cid is None:
            return resp(401, {"error": "invalid_client"})
        self.introspections.append((cid, hop))
        if hop is None:
            if self.tampered_active:
                return resp(200, {"active": True, "sub": V["user"]})
            if self.tampered_extra:
                return resp(200, {"active": False, "sub": V["user"], "zz_unlisted": "x"})
            return resp(200, {"active": False})
        if hop in self.inactive_hops:
            return resp(200, {"active": False})
        claims = copy.deepcopy(self.hop_claims[hop])
        out = {"active": True, **claims, "token_type": "Bearer", "scope": " ".join(claims["scope"])}
        if hop == "P1":
            out["aud"] = claims["aud"][0]          # string form exercises aud normalisation
        else:
            out.update(jti=f"jti-{hop}", nbf=claims["iat"], purpose="phase0 purpose")
        out.update(self.introspection_extra)
        for path, value in self.introspect_mutations.get(hop, {}).items():
            _set_path(out, path, value)
        return resp(200, out)

    def me_sessions(self, headers):
        auth = headers.get("Authorization", "")
        self.me_calls.append(auth)
        if auth == "Bearer " + self.admin_token:
            return resp(self.me_control_status, {"content": []})
        hdrs = [("WWW-Authenticate", self.me_tampered_challenge)] if self.me_tampered_challenge else []
        body = b"" if self.me_tampered_status == 401 else {"content": []}
        return resp(self.me_tampered_status, body, hdrs)

    def exchange(self, headers, form):
        if form["subject_token"] in self.tokens:
            return super().exchange(headers, form)
        if self._client(headers["Authorization"]) is None:
            return resp(401, {"error": "invalid_client"})
        if self.tampered_subject_issues:
            tok = self._sensitive(make_jwt({"sub": V["user"], "aud": [V["tool_aud"]]}))
            return resp(200, {"access_token": tok, "issued_token_type": h1.ACCESS_TOKEN_TYPE})
        if self.tampered_subject_echo:
            return resp(400, {"error": "invalid_grant " + form["subject_token"]})
        return resp(400, {"error": "invalid_grant", "error_description": "subject token rejected"})

    def token_of(self, hop):
        return next(t for t, h in self.tokens.items() if h == hop)


def make_runner(server=None, *, popen=None, port_chooser=None, **kw):
    out = io.StringIO()
    server = server or FakeH3Server()
    popen = popen or SeqPopen()
    r = h3.H3Runner(run_cmd=FakeCmd(), popen=popen, http=server, out=out, now=lambda: NOW, prefix=PREFIX,
                    port_chooser=port_chooser or (lambda: PORT), pf_ready_timeout=2.0, **kw)
    return r, out, server


def run_full(server=None, **kw):
    r, out, server = make_runner(server, **kw)
    code = r.run()
    return code, events(out), out.getvalue(), server, r


# ---------------------------------------------------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------------------------------------------------

class PinTests(unittest.TestCase):
    def test_pinned_files_byte_identical(self):
        for name, digest in PINNED.items():
            with open(os.path.join(HERE, name), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest, name)
        self.assertEqual(h3.H1_SHA256, PINNED["phase0_harness.py"])
        self.assertEqual(h3.H2_SHA256, PINNED["phase0_harness_h2.py"])
        self.assertEqual(h2.H1_SHA256, PINNED["phase0_harness.py"])

    def test_modules_shared(self):
        self.assertIs(h3.h2, h2)
        self.assertIs(h3.h1, h1)
        self.assertIs(sys.modules["phase0_harness_h2"], h2)
        self.assertTrue(issubclass(h3.H3Runner, h2.H2Runner))

    def _digests(self):
        return {n: h3._file_digest(os.path.join(HERE, n)) for n in PINNED}

    def test_h2_digest_mismatch_refused(self):
        before = self._digests()
        with mock.patch.object(h3, "H2_SHA256", "0" * 64):
            with self.assertRaises(ImportError):
                h3._load_h2()        # already imported: still refused
            saved = sys.modules.pop("phase0_harness_h2")
            try:
                with self.assertRaises(ImportError):
                    h3._load_h2()
                self.assertNotIn("phase0_harness_h2", sys.modules)
            finally:
                sys.modules["phase0_harness_h2"] = saved
        self.assertEqual(self._digests(), before)
        self.assertIs(h3._load_h2(), h2)

    def test_h1_digest_mismatch_refused(self):
        before = self._digests()
        saved = sys.modules.pop("phase0_harness_h2")
        try:
            with mock.patch.object(h3, "H1_SHA256", "f" * 64):
                with self.assertRaises(ImportError):
                    h3._load_h2()
            self.assertNotIn("phase0_harness_h2", sys.modules)
        finally:
            sys.modules["phase0_harness_h2"] = saved
        self.assertEqual(self._digests(), before)

    def test_foreign_module_refused(self):
        fake = types.ModuleType("phase0_harness_h2")
        fake.__file__ = "/tmp/elsewhere/phase0_harness_h2.py"
        with mock.patch.dict(sys.modules, {"phase0_harness_h2": fake}):
            with self.assertRaises(ImportError):
                h3._load_h2()
        self.assertIs(h3._load_h2(), h2)

    def test_loads_sibling_by_path_when_not_imported(self):
        saved = sys.modules.pop("phase0_harness_h2")
        try:
            mod = h3._load_h2()
            self.assertEqual(os.path.realpath(mod.__file__), os.path.realpath(os.path.join(HERE, "phase0_harness_h2.py")))
            self.assertIs(mod.h1, h1)
        finally:
            sys.modules["phase0_harness_h2"] = saved


class TamperHelperTests(unittest.TestCase):
    HEAD, BODY = b64u(b'{"alg":"RS256","typ":"at+jwt"}'), b64u(b'{"sub":"x"}')

    def token(self, sig: bytes) -> str:
        return f"{self.HEAD}.{self.BODY}.{b64u(sig)}"

    def test_rs256_sized_signature(self):
        sig = bytes((i * 7 + 3) % 256 for i in range(256))
        tok = self.token(sig)
        out = h3.tamper_jwt_signature(tok)
        o = out.split(".")
        self.assertEqual(o[:2], [self.HEAD, self.BODY])
        self.assertNotEqual(o[2], tok.split(".")[2])
        self.assertNotIn("=", o[2])
        new = base64.urlsafe_b64decode(o[2] + "=" * (-len(o[2]) % 4))
        self.assertEqual(len(new), 256)
        diff = [i for i in range(256) if new[i] != sig[i]]
        self.assertEqual(diff, [128])
        self.assertEqual(new[128], sig[128] ^ 0x01)
        info = h3.tamper_info(tok, out)
        self.assertEqual((info["signature_bytes"], info["flipped_byte_index"]), (256, 128))
        self.assertNotEqual(info["original_token_sha256_12"], info["tampered_token_sha256_12"])

    def test_fake_signature_and_involution(self):
        tok = make_jwt({"sub": "x"})
        out = h3.tamper_jwt_signature(tok)
        self.assertNotEqual(out, tok)
        self.assertEqual(h3.tamper_jwt_signature(out), tok)   # flipping the same bit twice restores it

    def test_last_char_only_counter_example(self):
        # 256 = 3*85 + 1: the final base64url char carries 2 data bits and 4 unused low-order bits.
        self.assertEqual(256 % 3, 1)
        self.assertEqual((6 - (256 * 8) % 6) % 6, 4)
        sig = bytes(range(256))
        seg = b64u(sig)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        last = alphabet.index(seg[-1])
        same_bytes = seg[:-1] + alphabet[last ^ 0x01]           # differs only in an unused bit
        self.assertNotEqual(same_bytes, seg)
        self.assertEqual(base64.urlsafe_b64decode(same_bytes + "=="), sig)     # identical bytes: not a tamper
        with self.assertRaises(h3.TamperError):                 # and the helper refuses it as non-canonical
            h3.tamper_jwt_signature(f"{self.HEAD}.{self.BODY}.{same_bytes}")
        out = h3.tamper_jwt_signature(self.token(sig))
        self.assertNotEqual(base64.urlsafe_b64decode(out.split(".")[2] + "=="), sig)

    def test_refusals(self):
        good = b64u(bytes(range(9)))
        for bad in (None, "a.b", "a.b.c.d", f"{self.HEAD}.{self.BODY}.", f".{self.BODY}.{good}",
                    f"{self.HEAD}.{self.BODY}.{good}=", f"{self.HEAD}.{self.BODY}.ab+c",
                    f"{self.HEAD}.{self.BODY}.abcde", f"{self.HEAD}.{self.BODY}.a b"):
            with self.assertRaises(h3.TamperError, msg=repr(bad)):
                h3.tamper_jwt_signature(bad)

    def test_identical_result_raises(self):
        tok = self.token(bytes(range(32)))
        seg = tok.split(".")[2]
        with mock.patch.object(h3, "_b64url_encode", side_effect=[seg, seg]):
            with self.assertRaises(h3.TamperError):
                h3.tamper_jwt_signature(tok)
        sig = bytes(range(32))
        real = h3._b64url_decode_strict
        calls = {"n": 0}

        def decode(s):
            calls["n"] += 1
            return sig if calls["n"] == 2 else real(s)
        with mock.patch.object(h3, "_b64url_decode_strict", side_effect=decode):
            with self.assertRaises(h3.TamperError):
                h3.tamper_jwt_signature(tok)


class TableTests(unittest.TestCase):
    def test_table_shape(self):
        t = h3.H3_EXPECTATIONS
        h3.validate_h3_expectations(t)
        self.assertEqual(len(h3.CASE_IDS), 16)
        self.assertEqual(t["introspector_role"], "sibling")
        c6 = t["cases"]["H3-C6"]
        self.assertEqual((c6["kind"], c6["h2_kind"], c6["source_case"], c6["subject"]),
                         ("chain", "exchange", "H2-P6", "H3-C5"))
        self.assertIn(("exp_bound", "H3-C5"), c6["checks"])
        self.assertIn(("sid_new", ["H3-C1", "H3-C2", "H3-C3", "H3-C4", "H3-C5"]), c6["checks"])
        for cid in ("H3-T1", "H3-T2", "H3-T3"):
            want = h3.TAMPER_CLAIM_T1 if cid == "H3-T1" else h3.TAMPER_CLAIM
            self.assertEqual(t["cases"][cid]["claim"], want)
            self.assertIn("not revocation evidence", t["cases"][cid]["claim"])
        self.assertIn("cause not distinguishable", h3.TAMPER_CLAIM_T1)
        self.assertNotIn("signature-integrity", h3.TAMPER_CLAIM_T1)
        self.assertEqual(t["cases"]["H3-T2"]["control_case"], "H3-C6")
        self.assertIn("H3-C6", t["cases"]["H3-T2"]["depends"])
        # H-2's own table is untouched by the derivation
        self.assertEqual(h2.H2_EXPECTATIONS["cases"]["H2-P6"]["subject"], "H2-P5")

    def test_validation_rejects(self):
        def bad(mut):
            t = copy.deepcopy(h3.H3_EXPECTATIONS)
            mut(t)
            with self.assertRaises(h1.HarnessError):
                h3.validate_h3_expectations(t)
        bad(lambda t: t["cases"]["H3-I1"].__setitem__("fields", [("sub", "fuzzy")]))
        bad(lambda t: t["cases"]["H3-I1"].__setitem__("fields", [("password", "eq")]))
        bad(lambda t: t["cases"]["H3-I1"].__setitem__("depends", []))
        bad(lambda t: t["cases"]["H3-T1"].pop("claim"))
        bad(lambda t: t["cases"]["H3-T2"].__setitem__("depends", ["H3-C5"]))
        bad(lambda t: t["cases"]["H3-N1"].__setitem__("kind", "other"))
        bad(lambda t: t["order"].reverse())
        bad(lambda t: t["cases"]["H3-C2"].__setitem__("subject", "H2-P1"))
        bad(lambda t: t["cases"]["H3-T3"].__setitem__("control_status", "200"))


class EvaluatorTests(unittest.TestCase):
    CLAIMS = {"sub": "u", "aud": ["a"], "client_id": "c", "scope": ["s1", "s2"], "exp": 10, "iat": 5,
              "sid": "sid-1", "act": {"sub": "w", "client_id": "c", "workload_id": "wl-1"},
              "tenant_id": "meridian", "identity_kind": "workforce", "azp": "c"}

    def test_modes(self):
        c = self.CLAIMS
        self.assertIsNone(h3.compare_field("aud", "eq", c, {"aud": "a"}))
        self.assertIsNone(h3.compare_field("scope", "eq", c, {"scope": "s2 s1"}))
        self.assertIsNone(h3.compare_field("exp", "eq", c, {"exp": 10.0}))
        self.assertIsNotNone(h3.compare_field("exp", "eq", c, {"exp": "10"}))
        self.assertIsNotNone(h3.compare_field("exp", "eq", c, {"exp": True}))
        self.assertIsNotNone(h3.compare_field("sub", "eq", c, {}))
        self.assertIsNotNone(h3.compare_field("iss", "eq", c, {"iss": "x"}))          # token lacks it
        self.assertIsNone(h3.compare_field("iss", "eq_if_present", c, {}))
        self.assertIsNotNone(h3.compare_field("iss", "eq_if_present", c, {"iss": "x"}))
        self.assertIsNone(h3.compare_field("token_use", "absent_ok", c, {}))
        self.assertIsNotNone(h3.compare_field("token_use", "absent_ok", c, {"token_use": "x"}))
        self.assertIsNotNone(h3.compare_field("sid", "absent_ok", c, {}))
        self.assertIsNone(h3.compare_field("act.sub", "eq", c, {"act": {"sub": "w"}}))
        self.assertIsNotNone(h3.compare_field("act.sub", "eq", c, {"act": "w"}))
        with self.assertRaises(h1.HarnessError):
            h3.compare_field("sub", "nope", c, {"sub": "u"})

    def test_introspection_output_is_allow_listed_and_sid_hashed(self):
        spec = h3.H3_EXPECTATIONS["cases"]["H3-I2"]
        claims = dict(self.CLAIMS, iss="i", token_use="t", authority_profile="p", authority_id="r",
                      subject_sid="root-sid-value")
        body = json.dumps({"active": True, **claims, "token_type": "Bearer", "secret_marker": "ZZSECRETZZ"})
        r = h3.evaluate_introspection("H3-I2", spec, 200, body, claims, NOW)
        self.assertEqual(r["result"], "pass", r["mismatches"])
        text = json.dumps(r)
        self.assertNotIn("ZZSECRETZZ", text)
        self.assertNotIn("root-sid-value", text)
        self.assertNotIn("sid-1", text)
        self.assertEqual(r["observed"]["fields"]["sid"]["value"], h3.sha12("sid-1"))
        r = h3.evaluate_introspection("H3-I2", spec, 200, json.dumps({"active": "true", **claims}), claims)
        self.assertIn("active is not true", r["mismatches"])
        r = h3.evaluate_introspection("H3-I2", spec, 401, json.dumps({"error": "invalid_client",
                                                                       "error_description": "ZZDESCZZ"}), claims)
        self.assertEqual(r["result"], "fail")
        self.assertNotIn("ZZDESCZZ", json.dumps(r))

    def test_tampered_introspection_evaluator(self):
        spec = h3.H3_EXPECTATIONS["cases"]["H3-T1"]
        self.assertEqual(h3.evaluate_tampered_introspection("H3-T1", spec, 200, '{"active":false}')["result"], "pass")
        for status, body in ((200, '{"active":true}'), (200, '{"active":false,"sub":"x"}'), (401, '{"active":false}'),
                             (200, ""), (200, '{"active":"false"}')):
            self.assertEqual(h3.evaluate_tampered_introspection("H3-T1", spec, status, body)["result"], "fail", body)

    def test_noauth_evaluator_accepts_empty_body(self):
        spec = h3.H3_EXPECTATIONS["cases"]["H3-N1"]
        ok = h3.evaluate_noauth_introspection("H3-N1", spec, 401, b"", [])
        self.assertEqual(ok["result"], "pass", ok["mismatches"])
        self.assertEqual(h3.evaluate_noauth_introspection("H3-N1", spec, 401, b"", [("WWW-Authenticate", "Basic")])["result"], "pass")
        r = h3.evaluate_noauth_introspection("H3-N1", spec, 401, '{"active":true}', [("WWW-Authenticate", "Bearer")])
        self.assertIn("active:true returned without client authentication", r["mismatches"])


class FullRunTests(unittest.TestCase):
    def assert_no_secrets(self, text, server, r):
        for s in server.secrets_seen + list(server.users.values()) + [p.reveal() for p in r.passwords.values()]:
            self.assertNotIn(s, text)
        self.assertNotIn("code=", text)
        self.assertNotIn("Basic ", text)

    def test_happy_path(self):
        code, evs, text, server, r = run_full()
        cs = cases_of(evs)
        self.assertEqual(list(cs), list(h3.CASE_IDS))
        for cid, c in cs.items():
            self.assertEqual(c["result"], "pass", (cid, c["mismatches"], c["observed"]))
        s = summary_of(evs)
        self.assertEqual(code, 0)
        self.assertEqual((s["package"], s["passed"], s["failed"], s["skipped"], s["aborted"], s["redaction_violation"],
                          s["cleanup_complete"], s["port_forward_leaked"], s["location_rewrites"]),
                         ("H-3", 16, 0, 0, False, False, True, False, 0))
        self.assertTrue(all(e["event"].startswith("h3_") and e["package"] == "H-3" for e in evs))
        self.assert_no_secrets(text, server, r)
        self.assertEqual(server.bad_urls, [])
        # Fresh H-3 identities (prefix passed in; template is p3h + 10 hex)
        self.assertTrue(h3.new_prefix_h3(lambda n: "ab" * n).startswith("p3h"))
        # claims/notes on T cases
        for cid in ("H3-T1", "H3-T2", "H3-T3"):
            self.assertEqual(cs[cid]["claim"], h3.TAMPER_CLAIM_T1 if cid == "H3-T1" else h3.TAMPER_CLAIM)
        self.assertIn("not revocation evidence", cs["H3-T1"]["note"])
        self.assertIn("cause not distinguishable", cs["H3-T1"]["note"])
        self.assertEqual(cs["H3-T2"]["note"], h3.H3_EXPECTATIONS["cases"]["H3-T2"]["note"])
        self.assertEqual(cs["H3-T2"]["observed"]["control_case"], "H3-C6")
        self.assertEqual(cs["H3-T3"]["observed"]["control_status"], 200)
        self.assertTrue(cs["H3-T3"]["observed"]["www_authenticate_contains_invalid_token"])
        self.assertEqual(cs["H3-T1"]["observed"]["flipped_byte_index"], 4)
        # introspection client and requests
        sib = f"{PREFIX}-sibling"
        self.assertEqual(server.introspections[:6], [(sib, f"P{n}") for n in range(1, 7)])
        self.assertEqual(server.introspections[6], (sib, None))         # T1 (tampered: unknown to the store)
        self.assertEqual(server.introspections[7], (None, "P1"))        # N1 (no client authentication)
        self.assertEqual(cs["H3-I1"]["observed"]["introspector"], sib)
        self.assertEqual(cs["H3-I1"]["observed"]["fields"]["aud"]["value"], [V["bff_aud"]])
        # the admin login token is never introspected
        for q in server.requests:
            if q["path"] == "/oauth/introspect":
                self.assertNotIn(server.admin_token, q["body"].decode())

    def test_introspection_immediately_after_chain(self):
        _code, _evs, _t, server, _r = run_full()
        paths = [(q["method"], q["path"]) for q in server.requests]
        tokens = [i for i, p in enumerate(paths) if p == ("POST", "/oauth/token")]
        last_chain = tokens[5]       # redemption + five exchanges
        self.assertEqual(paths[last_chain + 1:last_chain + 7], [("POST", "/oauth/introspect")] * 6)

    def test_tampered_tokens_used_once_and_never_printed(self):
        code, evs, text, server, _r = run_full()
        self.assertEqual(code, 0)
        t_admin = h3.tamper_jwt_signature(server.admin_token)
        t_c6 = h3.tamper_jwt_signature(server.token_of("P6"))
        t_c5 = h3.tamper_jwt_signature(server.token_of("P5"))
        for tok, where in ((t_admin, ("GET", "/api/me/sessions")), (t_c6, ("POST", "/oauth/introspect")),
                           (t_c5, ("POST", "/oauth/token"))):
            hits = [(q["method"], q["path"]) for q in server.requests
                    if tok in json.dumps(q["headers"]) or (q["body"] and tok in urllib.parse.unquote_plus(
                        q["body"].decode()))]
            self.assertEqual(hits, [where])
            self.assertNotIn(tok, text)
            self.assertNotIn(tok.split(".")[2], text)
        self.assertEqual(server.me_calls, ["Bearer " + server.admin_token, "Bearer " + t_admin])

    def test_raw_sids_and_unlisted_members_never_printed(self):
        s = FakeH3Server()
        s.introspection_extra = {"zz_secret_member": "ZZMEMBERZZ", "purpose": "ZZPURPOSEZZ"}
        code, evs, text, server, _r = run_full(s)
        self.assertEqual(code, 0)
        self.assertNotIn("ZZMEMBERZZ", text)
        self.assertNotIn("ZZPURPOSEZZ", text)
        case_text = json.dumps([e for e in evs if e["event"] == "h3_case"])
        for hop in ("P1", "P2", "P3", "P4", "P5", "P6"):
            self.assertNotIn(server.hop_claims[hop]["sid"], case_text)
        c2 = cases_of(evs)["H3-C2"]["observed"]["claims"]
        self.assertTrue(c2["sid"].startswith("sha256_12:") and c2["subject_sid"].startswith("sha256_12:"))


class FieldMismatchTests(unittest.TestCase):
    def check_only(self, server, failed, skipped=frozenset()):
        code, evs, text, server, r = run_full(server)
        cs = cases_of(evs)
        for cid, c in cs.items():
            want = "fail" if cid in failed else "skipped" if cid in skipped else "pass"
            self.assertEqual(c["result"], want, (cid, c["mismatches"]))
        self.assertEqual(code, 1)
        return cs, text

    def test_each_field_mismatch_fails_its_case(self):
        changed = {"sub": "other-sub", "aud": ["other-aud"], "client_id": "other-client", "scope": "openid",
                   "exp": lambda v: v + 1, "iat": lambda v: v - 1, "iss": "http://other", "act.sub": "other",
                   "act.client_id": "other", "token_use": "other", "authority_profile": "other",
                   "authority_id": "other", "subject_sid": "other-sid", "sid": "other-sid",
                   "tenant_id": "other-tenant", "identity_kind": "workload", "azp": "other-azp",
                   "act.workload_id": "other-wl", "token_type": "Basic"}
        for n in range(1, 7):
            cid = f"H3-I{n}"
            for item in h3.H3_EXPECTATIONS["cases"][cid]["fields"]:
                path = item[0]
                s = FakeH3Server()
                s.introspect_mutations = {f"P{n}": {path: changed[path]}}
                skipped = {"H3-T1"} if n == 6 else set()
                cs, _t = self.check_only(s, {cid}, skipped)
                self.assertTrue(any(m.startswith(path + ":") for m in cs[cid]["mismatches"]), (cid, path))
                self.assertFalse(cs[cid]["observed"]["fields"][path]["match"])

    def test_dropping_required_fields_fails(self):
        # iss, tenant_id, identity_kind, azp, act.workload_id and token_type are now required (review fix).
        for path in ("sub", "aud", "exp", "act.client_id", "sid", "iss", "tenant_id", "identity_kind", "azp",
                     "act.workload_id", "token_type"):
            s = FakeH3Server()
            s.introspect_mutations = {"P3": {path: DROP}}
            self.check_only(s, {"H3-I3"})
        s = FakeH3Server()
        s.introspect_mutations = {"P1": {"sid": DROP}}     # P1 carries sid: absent_ok needs it echoed
        self.check_only(s, {"H3-I1"})

    def test_genuine_token_inactive_fails(self):
        for n in range(1, 6):
            s = FakeH3Server()
            s.inactive_hops = {f"P{n}"}
            cs, _t = self.check_only(s, {f"H3-I{n}"})
            self.assertIn("active is not true", cs[f"H3-I{n}"]["mismatches"])
        s = FakeH3Server()
        s.inactive_hops = {"P6"}
        cs, _t = self.check_only(s, {"H3-I6"}, {"H3-T1"})
        self.assertIn("H3-I6", cs["H3-T1"]["observed"]["skipped_reason"])

    def test_t1_active_true_fails(self):
        s = FakeH3Server()
        s.tampered_active = True
        cs, _t = self.check_only(s, {"H3-T1"})
        self.assertIn("active is not false", cs["H3-T1"]["mismatches"])

    def test_t1_extra_members_fail(self):
        s = FakeH3Server()
        s.tampered_extra = True
        cs, text = self.check_only(s, {"H3-T1"})
        self.assertEqual(cs["H3-T1"]["observed"]["extra_member_count"], 2)
        self.assertEqual(cs["H3-T1"]["observed"]["extra_members"], ["sub"])
        self.assertNotIn("zz_unlisted", text)

    def test_t2_token_issued_fails(self):
        s = FakeH3Server()
        s.tampered_subject_issues = True
        cs, text = self.check_only(s, {"H3-T2"})
        self.assertIn("access_token present in denial body", cs["H3-T2"]["mismatches"])
        for secret in s.secrets_seen:
            self.assertNotIn(secret, text)

    def test_t3_status_200_fails(self):
        s = FakeH3Server()
        s.me_tampered_status = 200
        cs, _t = self.check_only(s, {"H3-T3"})
        self.assertIn("status 200 != 401", cs["H3-T3"]["mismatches"])

    def test_t3_missing_invalid_token_challenge_fails(self):
        s = FakeH3Server()
        s.me_tampered_challenge = "Bearer"
        cs, text = self.check_only(s, {"H3-T3"})
        self.assertIn("WWW-Authenticate does not contain invalid_token", cs["H3-T3"]["mismatches"])

    def test_t3_control_failure_sends_no_tampered_request(self):
        s = FakeH3Server()
        s.me_control_status = 403
        cs, _t = self.check_only(s, {"H3-T3"})
        self.assertTrue(cs["H3-T3"]["mismatches"][0].startswith("control failed"))
        self.assertFalse(cs["H3-T3"]["observed"]["signature_result"])
        self.assertEqual(s.me_calls, ["Bearer " + s.admin_token])

    def test_n1_200_fails(self):
        s = FakeH3Server()
        s.noauth_status = 200
        s.noauth_active = True
        cs, _t = self.check_only(s, {"H3-N1"})
        self.assertIn("status 200 != 401", cs["H3-N1"]["mismatches"])
        self.assertIn("active:true returned without client authentication", cs["H3-N1"]["mismatches"])

    def test_n1_without_challenge_still_requires_401_and_no_active_true(self):
        s = FakeH3Server()
        s.noauth_challenge = None
        code, evs, _text, _server, _runner = run_full(s)
        cs = cases_of(evs)
        self.assertEqual(code, 0)
        self.assertEqual(cs["H3-N1"]["result"], "pass")


class DependencyTests(unittest.TestCase):
    def test_c1_failure_skips_everything_but_t3(self):
        code, evs, _t, server, _r = run_full(FakeH3Server(claim_overrides={"P1": {"roles": []}}))
        cs = cases_of(evs)
        self.assertEqual(cs["H3-C1"]["result"], "fail")
        self.assertEqual(cs["H3-T3"]["result"], "pass")
        for cid in h3.CASE_IDS:
            if cid not in ("H3-C1", "H3-T3"):
                self.assertEqual(cs[cid]["result"], "skipped", cid)
        self.assertEqual(server.introspections, [])
        self.assertEqual(code, 1)

    def test_c5_failure_skips_dependents(self):
        code, evs, _t, _s, _r = run_full(FakeH3Server(claim_overrides={"P5": {"aud": ["other"]}}))
        cs = cases_of(evs)
        self.assertEqual(cs["H3-C5"]["result"], "fail")
        for cid in ("H3-C6", "H3-I5", "H3-I6", "H3-T1", "H3-T2"):
            self.assertEqual(cs[cid]["result"], "skipped", cid)
        for cid in ("H3-C1", "H3-C2", "H3-C3", "H3-C4", "H3-I1", "H3-I2", "H3-I3", "H3-I4", "H3-T3", "H3-N1"):
            self.assertEqual(cs[cid]["result"], "pass", cid)
        self.assertEqual(code, 1)

    def test_c6_failure_skips_t2_control_dependency(self):
        s = FakeH3Server(exchange_overrides={"P6": (400, {"error": "invalid_target"})})
        code, evs, _t, _s, _r = run_full(s)
        cs = cases_of(evs)
        self.assertEqual(cs["H3-C6"]["result"], "fail")
        for cid in ("H3-I6", "H3-T1", "H3-T2"):
            self.assertEqual(cs[cid]["result"], "skipped", cid)
        self.assertEqual(code, 1)


class RedactionTests(unittest.TestCase):
    def test_echoed_tampered_subject_is_redacted_and_forces_exit_2(self):
        s = FakeH3Server()
        s.tampered_subject_echo = True
        code, evs, text, server, _r = run_full(s)
        self.assertEqual(code, 2)
        self.assertTrue(summary_of(evs)["redaction_violation"])
        self.assertIn("<redacted>", text)
        self.assertNotIn(h3.tamper_jwt_signature(server.token_of("P5")), text)
        self.assertEqual(cases_of(evs)["H3-T2"]["result"], "fail")

    def test_registered_sensitive_values(self):
        r, _out, s = make_runner()
        self.assertEqual(r.run(), 0)
        values = r.redactor._values
        for tok in (h3.tamper_jwt_signature(s.admin_token), h3.tamper_jwt_signature(s.token_of("P6")),
                    h3.tamper_jwt_signature(s.token_of("P5")), s.admin_token, s.token_of("P1"), s.token_of("P6")):
            self.assertIn(tok, values)
        for p in r.passwords.values():
            self.assertIn(p.reveal(), values)
        for st in s.states_seen:
            self.assertIn(st, values)


class AbortAndCleanupTests(unittest.TestCase):
    def test_introspection_5xx_aborts_and_cleans_up(self):
        s = FakeH3Server(overrides={("POST", "/oauth/introspect"): resp(503, {"error": "down"})})
        code, evs, _t, server, _r = run_full(s)
        cs = cases_of(evs)
        summ = summary_of(evs)
        self.assertEqual(code, 2)
        self.assertTrue(summ["aborted"])
        self.assertEqual(cs["H3-I1"]["result"], "fail")
        self.assertEqual(cs["H3-N1"]["observed"]["skipped_reason"], "aborted")
        cleanup = [e for e in evs if e["event"] == "h3_cleanup"]
        self.assertTrue(cleanup and all(e["ok"] for e in cleanup))
        self.assertTrue(summ["cleanup_complete"])
        self.assertTrue(any(m == "DELETE" and p.startswith("/users/") for m, p in server.calls))
        self.assertEqual(len(server.revoked_sessions), 1)

    def test_cleanup_order_matches_h2(self):
        _code, evs, _t, _s, _r = run_full()
        steps = []
        for e in evs:
            if e["event"] == "h3_cleanup":
                head = e["step"] if not e["step"].startswith("revoke_sessions") else ":".join(e["step"].split(":")[:2])
                if head not in steps:
                    steps.append(head)
        self.assertEqual(steps[:6], ["revoke_sessions:user", "revoke_sessions:nomember", "revoke_route:R4",
                                     "revoke_route:R3", "revoke_route:R2", "revoke_route:R1"])
        self.assertEqual(steps[-1], "disable_application:sibling")

    def test_verification_failure_makes_no_calls(self):
        r, out, server = make_runner()
        r.run_cmd = FakeCmd(**{"V-2": h1.subprocess.CompletedProcess([], 1, "", "nope")})
        self.assertEqual(r.run(), 2)
        self.assertEqual(server.calls, [])
        self.assertEqual(summary_of(events(out))["skipped"], 16)

    def test_port_forward_lost_during_introspection(self):
        s = FakeH3Server()
        holder = {}

        def kill(headers, body):
            holder["r"].pf.returncode = 1
            return None
        s.overrides[("POST", "/oauth/introspect")] = kill
        ports = iter([PORT, PORT + 1])
        popen = SeqPopen([PORT, PORT + 1])
        r, out, server = make_runner(s, popen=popen, port_chooser=lambda: next(ports))
        holder["r"] = r
        code = r.run()
        evs = events(out)
        self.assertEqual(code, 2)
        self.assertTrue(any(e["event"] == "h3_port_forward_restart" and e["ok"] for e in evs))
        self.assertTrue(summary_of(evs)["cleanup_complete"])


class PlanModeTests(unittest.TestCase):
    def test_plan_mode_makes_no_calls(self):
        buf = io.StringIO()
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("run")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("popen")), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("socket")), \
                mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("urlopen")), \
                mock.patch.object(urllib.request.OpenerDirector, "open", side_effect=AssertionError("open")), \
                mock.patch.object(h3.H3Runner, "__init__", side_effect=AssertionError("runner")):
            self.assertEqual(h3.main(["--package", "h3"], out=buf), 0)
        evs = [json.loads(l) for l in buf.getvalue().splitlines()]
        self.assertEqual(evs[0]["event"], "h3_plan")
        self.assertEqual(evs[0]["introspector"], "<p>-sibling")
        self.assertTrue(any("last_seen" in x for x in evs[0]["side_effects"]))
        self.assertEqual(len([e for e in evs if e["event"] == "h3_plan_verify"]), 11)
        plan_cases = [e for e in evs if e["event"] == "h3_plan_case"]
        self.assertEqual([e["case_id"] for e in plan_cases], list(h3.CASE_IDS))
        self.assertEqual(evs[-1]["event"], "h3_plan_cleanup")
        self.assertTrue(all(e["package"] == "H-3" for e in evs))
        t2 = next(e for e in plan_cases if e["case_id"] == "H3-T2")
        self.assertEqual((t2["audience"], t2["requester"]), ("tool:meridian:<p>-tool", "<p>-gateway-broker"))
        c6 = next(e for e in plan_cases if e["case_id"] == "H3-C6")
        self.assertIn(["claim", "authority_id", "<R4>"], c6["checks"])

    def test_package_flag_required(self):
        with mock.patch("sys.stderr", io.StringIO()):
            for argv in ([], ["--package", "h2"], ["--execute"]):
                with self.assertRaises(SystemExit, msg=argv):
                    h3.main(argv, out=io.StringIO())

    def test_execute_uses_runner_and_installs_signals(self):
        class R:
            def __init__(self, out):
                self.out = out

            def run(self):
                return 7
        with mock.patch.object(h3.signal, "signal") as sig:
            self.assertEqual(h3.main(["--package", "h3", "--execute"], out=io.StringIO(), runner_factory=R), 7)
        self.assertEqual({c.args[0] for c in sig.call_args_list}, {h3.signal.SIGTERM, h3.signal.SIGHUP})


if __name__ == "__main__":
    unittest.main()


class ReviewFixTests(unittest.TestCase):
    """Fixes from the independent H-3 safety review."""

    def test_cleanup_session_ids_are_hashed_in_output(self):
        r, out, _server = make_runner()[:3]
        r.emit({"event": "cleanup", "step": "revoke_sessions:user:0f1e2d3c-raw-session-id", "ok": True})
        r.emit({"event": "cleanup", "step": "revoke_sessions:user:session", "ok": False})
        text = out.getvalue()
        self.assertNotIn("0f1e2d3c-raw-session-id", text)
        self.assertIn(h3.sha12("0f1e2d3c-raw-session-id"), text)
        self.assertIn("revoke_sessions:user:session", text)   # fixed failure label is not an id

    def test_full_run_never_prints_raw_sids(self):
        code, evs, text, server, r = run_full()
        self.assertEqual(code, 0)
        for hop, claims in server.hop_claims.items():
            for key in ("sid", "subject_sid"):
                if claims.get(key):
                    self.assertNotIn(str(claims[key]), text, (hop, key))

    def test_t2_note_does_not_claim_cause(self):
        note = h3.H3_EXPECTATIONS["cases"]["H3-T2"]["note"]
        self.assertIn("does not distinguish the cause", note)
        self.assertIn("expected to exercise", note)

    def test_token_type_literal_required_on_exchanged_tokens(self):
        for n in range(2, 7):
            fields = h3.H3_EXPECTATIONS["cases"][f"H3-I{n}"]["fields"]
            self.assertIn(("token_type", h3.LITERAL_MODE, "Bearer"), fields)
        self.assertFalse(any(f[0] == "token_type" for f in h3.H3_EXPECTATIONS["cases"]["H3-I1"]["fields"]))
