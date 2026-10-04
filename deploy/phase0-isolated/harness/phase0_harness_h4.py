#!/opt/homebrew/bin/python3.13
"""H-4: isolated root-session revocation and subject_sid propagation test.

Runs the pinned H-3 chain and positive controls, revokes only the newly created
test user's root session, then checks all six tokens are inactive and that an
exchange using an already-issued descendant token is denied. No production
identity, route, broker, namespace or cluster-scoped resource is changed.

Without --execute this prints a plan and makes no network or subprocess calls.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import secrets
import signal
import sys
import urllib.parse
from typing import Any, Callable

HERE = os.path.dirname(os.path.abspath(__file__))
H3_PATH = os.path.join(HERE, "phase0_harness_h3.py")
H3_SHA256 = "6110ad051ea60ec4adb6a03d9360f125cce03a9ff93f8b358225ec1163641da0"


def load_h3() -> Any:
    with open(H3_PATH, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != H3_SHA256:
            raise ImportError("H-3 harness differs from the reviewed source")
    existing = sys.modules.get("phase0_harness_h3")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(H3_PATH):
            raise ImportError("H-3 module imported from an unexpected path")
        return existing
    spec = importlib.util.spec_from_file_location("phase0_harness_h3", H3_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load H-3 harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase0_harness_h3"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("phase0_harness_h3", None)
        raise
    return module


h3 = load_h3()
h2 = h3.h2
h1 = h3.h1
PACKAGE = "H-4"
PREFIX_HEAD = "p4h"
EXTRA_ORDER = ("H4-R1",) + tuple(f"H4-I{i}" for i in range(1, 7)) + ("H4-X1",)


def extra_cases() -> dict[str, dict]:
    base = tuple(h3.H3_EXPECTATIONS["order"])
    out = {
        "H4-R1": {
            "class": "root_session_revoke", "kind": "root_revoke", "depends": list(base),
            "description": "revoke the newly created human login's exact root session at its current revision",
        },
    }
    for i in range(1, 7):
        out[f"H4-I{i}"] = {
            "class": "post_revoke_introspection", "kind": "inactive", "token_case": f"H3-C{i}",
            "depends": ["H4-R1", f"H3-C{i}"], "status": 200, "active": False,
            "only_fields": ["active"],
            "description": f"the formerly active H3-C{i} token introspects as exactly active:false after root revoke",
        }
    out["H4-X1"] = {
        "class": "post_revoke_exchange", "kind": "exchange_denial", "depends": ["H4-R1", "H3-C5"],
        "requester": "broker", "subject": "H3-C5", "audience": "{tool_aud}", "scope": h3.SCOPE,
        "denial": {"status": 400, "error": "invalid_grant"},
        "description": "the broker cannot redeem the previously issued Agent-to-gateway token after root revoke",
    }
    return out


class H4Runner(h3.H3Runner):
    def __init__(self, *, prefix: str | None = None,
                 token_hex: Callable[[int], str] = secrets.token_hex, **kw: Any):
        table = copy.deepcopy(h3.H3_EXPECTATIONS)
        super().__init__(expectations=table, prefix=prefix or PREFIX_HEAD + token_hex(5), **kw)
        self.h3_case_ids = tuple(table["order"])
        table["order"].extend(EXTRA_ORDER)
        table["cases"].update(extra_cases())
        self.case_ids = tuple(table["order"])

    def emit(self, event: dict) -> None:
        ev = dict(event)
        step = ev.get("step")
        if isinstance(step, str):
            match = h3._SESSION_STEP.match(step)
            if match:
                ev["step"] = f"{match.group(1)}:{h3.sha12(match.group(2))}"
        name = str(ev.get("event", ""))
        for prefix in ("h3_", "h2_", "h4_"):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        ev["event"] = "h4_" + name
        ev["package"] = PACKAGE
        h1.Runner.emit(self, ev)

    def _record(self, result: dict) -> dict:
        return super()._record(result)

    def _root_revoke(self, cid: str, spec: dict) -> None:
        root = self.env.sids.get("H3-C1")
        user = self.h2.users.get("user")
        if not h2._safe_id(root) or not h2._safe_id(user) or self.admin_token is None:
            self._record(h3.h3_case_result(cid, spec, {}, ["root session, test user or admin token unavailable"]))
            return
        base = f"/admin/tenants/{h2.TENANT}/sessions"
        query = urllib.parse.urlencode({"principalId": str(user), "status": "ACTIVE", "size": 100})
        status, raw = self.request("GET", f"{base}?{query}", bearer=self.admin_token, abort_on_5xx=False)
        self._check_5xx(cid, status)
        doc = h2.parse_json(raw)
        items = doc.get("content") if isinstance(doc, dict) else doc
        total = doc.get("totalElements") if isinstance(doc, dict) else None
        matches = [it for it in items if isinstance(it, dict) and it.get("id") == root
                   and it.get("principalId") == user and it.get("status") == "ACTIVE"] if isinstance(items, list) else []
        if status != 200 or len(matches) != 1 or (isinstance(total, int) and total > len(items)):
            self._record(h3.h3_case_result(cid, spec, {"list_status": status, "matches": len(matches)},
                                           ["exact active test root session not found"])); return
        revision = matches[0].get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            self._record(h3.h3_case_result(cid, spec, {}, ["root session revision invalid"])); return
        status, raw = self.request("POST", f"{base}/{root}/revoke", bearer=self.admin_token,
                                   json_body={"expectedRevision": revision}, abort_on_5xx=False)
        self._check_5xx(cid, status)
        doc = h2.parse_json(raw)
        ok = status == 200 and isinstance(doc, dict) and doc.get("id") == root and doc.get("status") == "REVOKED"
        observed = {"list_status": 200, "revoke_status": status, "root_sid": h3.sha12(root),
                    "returned_revoked": bool(ok)}
        self._record(h3.h3_case_result(cid, spec, observed, [] if ok else ["root revoke not confirmed"]))

    def _inactive(self, cid: str, spec: dict) -> None:
        token = self.tokens.get(spec["token_case"])
        who = self._introspector()
        if token is None or who is None:
            self._record(h3.h3_case_result(cid, spec, {}, ["token or introspection client unavailable"])); return
        status, _headers, raw = self._introspect(token, who)
        result = h3.evaluate_tampered_introspection(cid, spec, status, raw)
        result["observed"].update(source_case=spec["token_case"], token_sha256_12=h1.token_hash(token.reveal()))
        self._record(result)
        self._check_5xx(cid, status)

    def _exchange_denial(self, cid: str, spec: dict) -> None:
        token = self.tokens.get(spec["subject"])
        secret = self.client_secrets.get(spec["requester"])
        if token is None or secret is None:
            self._record(h3.h3_case_result(cid, spec, {}, ["subject token or broker secret unavailable"])); return
        client = self.names["clients"][spec["requester"]]["clientId"]
        try:
            audience = h2.resolve(spec["audience"], self.env.variables)
        except h2.UnknownValue:
            self._record(h3.h3_case_result(cid, spec, {}, ["test audience unavailable"])); return
        form = {"grant_type": h3.TOKEN_EXCHANGE_GRANT, "subject_token": token.reveal(),
                "subject_token_type": h3.ACCESS_TOKEN_TYPE, "requested_token_type": h3.ACCESS_TOKEN_TYPE,
                "audience": audience, "scope": spec["scope"]}
        status, raw = self.request("POST", "/oauth/token", form=form, basic=(client, secret), abort_on_5xx=False)
        self._register_body_tokens(raw)
        result = h2.evaluate_denial(cid, spec, status, raw)
        result["observed"].pop("error_description", None)
        result["observed"].update(subject_case=spec["subject"], requester=client)
        self._record(result)
        self._check_5xx(cid, status)

    def run_cases(self) -> None:
        all_ids = self.case_ids
        try:
            self.case_ids = self.h3_case_ids
            h3.H3Runner.run_cases(self)
        finally:
            self.case_ids = all_ids
        handlers = {"root_revoke": self._root_revoke, "inactive": self._inactive,
                    "exchange_denial": self._exchange_denial}
        for cid in EXTRA_ORDER:
            spec = self.expectations["cases"][cid]
            blocked = [dep for dep in spec["depends"] if self.results.get(dep, {}).get("result") != "pass"]
            if blocked:
                self._record(h2.skipped_case(cid, spec, f"prerequisite {', '.join(blocked)} did not pass"))
                continue
            handlers[spec["kind"]](cid, spec)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-4 isolated root-session revocation harness")
    parser.add_argument("--package", required=True, choices=("h4",))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 13):
        return 2
    if not args.execute:
        for ev in h3.plan_events():
            ev = {**ev, "event": ev["event"].replace("h3_", "h4_", 1), "package": PACKAGE}
            if ev["event"] == "h4_plan":
                ev["prefix_template"] = "p4h + secrets.token_hex(5)"
            print(json.dumps(ev))
        for cid in EXTRA_ORDER:
            spec = extra_cases()[cid]
            print(json.dumps({"event": "h4_plan_case", "package": PACKAGE, "case_id": cid,
                              "expected": spec["description"], "depends": spec["depends"]}))
        return 0
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt(f"signal {signum}")))
    return H4Runner().run()


if __name__ == "__main__":
    sys.exit(main())
