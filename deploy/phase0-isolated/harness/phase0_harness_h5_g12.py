#!/opt/homebrew/bin/python3.13
"""H-5/G-12: test route revoke reach at Axiom introspection and exchange only."""

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
from typing import Any, Callable

HERE = os.path.dirname(os.path.abspath(__file__))
H3_PATH = os.path.join(HERE, "phase0_harness_h3.py")
H3_SHA256 = "6110ad051ea60ec4adb6a03d9360f125cce03a9ff93f8b358225ec1163641da0"
PACKAGE = "H-5/G-12"
EXTRA = ("H5-G12-R", "H5-G12-I", "H5-G12-C", "H5-G12-X")


def load_h3() -> Any:
    with open(H3_PATH, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != H3_SHA256:
            raise ImportError("H-3 source differs from reviewed version")
    existing = sys.modules.get("phase0_harness_h3")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(H3_PATH):
            raise ImportError("H-3 imported from unexpected path")
        return existing
    spec = importlib.util.spec_from_file_location("phase0_harness_h3", H3_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load H-3")
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase0_harness_h3"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("phase0_harness_h3", None)
        raise
    return module


h3 = load_h3()
h2, h1 = h3.h2, h3.h1


class G12Runner(h3.H3Runner):
    def __init__(self, *, prefix: str | None = None,
                 token_hex: Callable[[int], str] = secrets.token_hex, **kw: Any):
        super().__init__(expectations=copy.deepcopy(h3.H3_EXPECTATIONS),
                         prefix=prefix or "p5r" + token_hex(5), **kw)
        self.prior_ids = self.case_ids
        specs = {
            EXTRA[0]: ("revoke the disposable R4 resource route after successful issuance", list(self.prior_ids)),
            EXTRA[1]: ("previously issued resource token C6 introspects inactive", [EXTRA[0]]),
            EXTRA[2]: ("unrelated still-active gateway token C5 remains introspectable", [EXTRA[0]]),
            EXTRA[3]: ("broker cannot exchange C5 to the revoked R4 target", [EXTRA[0], EXTRA[2]]),
        }
        for cid, (description, deps) in specs.items():
            self.expectations["order"].append(cid)
            self.expectations["cases"][cid] = {"class": "route_revocation_characterization",
                                               "kind": "route_revoke_check", "depends": deps,
                                               "description": description}
        self.case_ids = tuple(self.expectations["order"])
        self.r4_revoked = False

    def emit(self, event: dict) -> None:
        ev = dict(event)
        step = ev.get("step")
        if isinstance(step, str):
            match = h3._SESSION_STEP.match(step)
            if match:
                ev["step"] = f"{match.group(1)}:{h3.sha12(match.group(2))}"
        name = str(ev.get("event", ""))
        for prefix in ("h3_", "h2_", "h5_"):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        ev["event"] = "h5_" + name
        ev["package"] = PACKAGE
        h1.Runner.emit(self, ev)

    def _revoke_r4(self, cid: str, spec: dict) -> None:
        rid = self.h2.routes.get("R4")
        if not h2._safe_id(rid):
            self._record(h3.h3_case_result(cid, spec, {}, ["R4 id unavailable"])); return
        path = f"/admin/tenants/{h2.TENANT}/agent-exchange/routes/{rid}/revoke"
        status, raw = self.request("POST", path, bearer=self.admin_token, abort_on_5xx=False)
        self._check_5xx(cid, status)
        doc = h2.parse_json(raw)
        ok = status == 200 and isinstance(doc, dict) and doc.get("id") == rid \
            and doc.get("status") == "REVOKED"
        self.r4_revoked = ok
        self._record(h3.h3_case_result(cid, spec, {"status": status, "returned_revoked": ok},
                                       [] if ok else ["R4 revoke not confirmed"]))

    def _introspect_state(self, cid: str, spec: dict, token_case: str, expected: bool) -> None:
        token = self.tokens.get(token_case)
        who = self._introspector()
        if token is None or who is None:
            self._record(h3.h3_case_result(cid, spec, {}, ["token or introspector unavailable"])); return
        status, _headers, raw = self._introspect(token, who)
        doc = h2.parse_json(raw)
        active = doc.get("active") if isinstance(doc, dict) else None
        # Inactivity must not leak claims. The active control requires the correct subject.
        ok = status == 200 and active is expected and (expected or set(doc) == {"active"})
        if expected:
            ok = ok and doc.get("sub") == self.h2.users["user"]
        self._record(h3.h3_case_result(cid, spec,
                                       {"status": status, "active": active, "source_case": token_case},
                                       [] if ok else ["introspection state mismatch"]))
        self._check_5xx(cid, status)

    def _exchange_denied(self, cid: str, spec: dict) -> None:
        token = self.tokens.get("H3-C5")
        secret = self.client_secrets.get("broker")
        if token is None or secret is None:
            self._record(h3.h3_case_result(cid, spec, {}, ["subject token or broker unavailable"])); return
        form = {"grant_type": h2.TOKEN_EXCHANGE_GRANT, "subject_token": token.reveal(),
                "subject_token_type": h2.ACCESS_TOKEN_TYPE, "requested_token_type": h2.ACCESS_TOKEN_TYPE,
                "audience": self.names["applications"]["tool"]["audience"], "scope": h2.SCOPE}
        status, raw = self.request("POST", "/oauth/token", form=form,
                                   basic=(self.names["clients"]["broker"]["clientId"], secret),
                                   abort_on_5xx=False)
        self._register_body_tokens(raw)
        doc = h2.parse_json(raw)
        error = doc.get("error") if isinstance(doc, dict) else None
        issued = isinstance(doc, dict) and bool(doc.get("access_token"))
        ok = status == 400 and error in ("invalid_target", "invalid_grant") and not issued
        self._record(h3.h3_case_result(cid, spec, {"status": status, "error": error,
                                                 "access_token_present": issued},
                                       [] if ok else ["revoked route still exchangeable or unexpected response"]))
        self._check_5xx(cid, status)

    def run_cases(self) -> None:
        all_ids = self.case_ids
        try:
            self.case_ids = self.prior_ids
            h3.H3Runner.run_cases(self)
        finally:
            self.case_ids = all_ids
        for cid in EXTRA:
            spec = self.expectations["cases"][cid]
            if any(self.results.get(dep, {}).get("result") != "pass" for dep in spec["depends"]):
                self._record(h2.skipped_case(cid, spec, "prerequisite failed")); continue
            if cid == EXTRA[0]:
                self._revoke_r4(cid, spec)
            elif cid == EXTRA[1]:
                self._introspect_state(cid, spec, "H3-C6", False)
            elif cid == EXTRA[2]:
                self._introspect_state(cid, spec, "H3-C5", True)
            else:
                self._exchange_denied(cid, spec)

    def cleanup_steps(self):
        steps = list(super().cleanup_steps())
        return [(name, fn) for name, fn in steps if not (self.r4_revoked and name == "revoke_route:R4")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-5 G-12 isolated route revoke characterization")
    parser.add_argument("--package", required=True, choices=("h5-g12",))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 13):
        return 2
    if not args.execute:
        print(json.dumps({"event": "h5_plan", "package": PACKAGE, "mode": "dry",
                          "namespace": h2.NAMESPACE, "context": h2.CONTEXT,
                          "prefix_template": "p5r + secrets.token_hex(5)",
                          "h3_sha256": H3_SHA256, "cases": EXTRA,
                          "cleanup": "R4 revoked once; ordinary H-3 cleanup handles other resources"}))
        return 0
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt(f"signal {signum}")))
    return G12Runner().run()


if __name__ == "__main__":
    sys.exit(main())
