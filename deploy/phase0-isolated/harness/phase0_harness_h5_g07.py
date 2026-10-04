#!/opt/homebrew/bin/python3.13
"""H-5/G-07: characterize cross-application workforce exchange in TEST-X only."""

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
PACKAGE = "H-5/G-07"
CASE_ID = "H5-G07"


def load_h3() -> Any:
    with open(H3_PATH, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != H3_SHA256:
            raise ImportError("H-3 source differs from reviewed version")
    existing = sys.modules.get("phase0_harness_h3")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(H3_PATH):
            raise ImportError("H-3 imported from an unexpected path")
        return existing
    spec = importlib.util.spec_from_file_location("phase0_harness_h3", H3_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load H-3 source")
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


class G07Runner(h3.H3Runner):
    def __init__(self, *, prefix: str | None = None,
                 token_hex: Callable[[int], str] = secrets.token_hex, **kw: Any):
        super().__init__(expectations=copy.deepcopy(h3.H3_EXPECTATIONS),
                         prefix=prefix or "p5x" + token_hex(5), **kw)
        self.prior_ids = self.case_ids
        self.expectations["order"].append(CASE_ID)
        self.expectations["cases"][CASE_ID] = {
            "class": "cross_application_characterization", "kind": "workforce_exchange",
            "depends": list(self.prior_ids),
            "description": "grant user app-B access, then exchange an app-A human token through app-B workload; classify 200 vs invalid_grant",
        }
        self.case_ids = tuple(self.expectations["order"])
        self.extra_membership_id: str | None = None

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

    def run_cases(self) -> None:
        all_ids = self.case_ids
        try:
            self.case_ids = self.prior_ids
            h3.H3Runner.run_cases(self)
        finally:
            self.case_ids = all_ids
        spec = self.expectations["cases"][CASE_ID]
        if any(self.results.get(dep, {}).get("result") != "pass" for dep in spec["depends"]):
            self._record(h2.skipped_case(CASE_ID, spec, "prerequisite failed"))
            return
        app = self.h2.apps["sibling"]
        base = f"/admin/tenants/{h2.TENANT}/applications/{app}/access"
        role_key = f"{self.prefix}-cross-app-role"
        doc = self._admin_call("cross_app_role", "POST", f"{base}/roles", {
            "roleKey": role_key, "displayName": role_key, "description": h2.DESCRIPTION,
            "permissions": [h2.SCOPE], "permissionEffects": {h2.SCOPE: "allow"}})
        role_id = self._require_id("cross_app_role", doc.get("id"))
        doc = self._admin_call("cross_app_membership", "POST", f"{base}/memberships", {
            "principalId": self.h2.users["user"], "assignmentSource": h2.ASSIGNMENT_SOURCE})
        self.extra_membership_id = self._require_id("cross_app_membership", doc.get("id"))
        self._admin_call("cross_app_membership_role", "POST",
                         f"{base}/memberships/{self.extra_membership_id}/roles",
                         {"roleId": role_id, "assignmentSource": h2.ASSIGNMENT_SOURCE}, expect=200)

        source = self.tokens[self.h3_table["p1_case"]]
        target_client = self.names["clients"]["sibling"]["clientId"]
        target_secret = self.client_secrets["sibling"]
        target_audience = self.names["applications"]["sibling"]["audience"]
        form = {"grant_type": h2.TOKEN_EXCHANGE_GRANT, "subject_token": source.reveal(),
                "subject_token_type": h2.ACCESS_TOKEN_TYPE, "requested_token_type": h2.ACCESS_TOKEN_TYPE,
                "audience": target_audience, "scope": h2.SCOPE}
        status, raw = self.request("POST", "/oauth/token", form=form,
                                   basic=(target_client, target_secret), abort_on_5xx=False)
        self._register_body_tokens(raw)
        doc = h2.parse_json(raw)
        observed: dict = {"status": status, "source_app": self.h2.apps["bff"], "target_app": app}
        mismatches: list[str] = []
        if status == 200:
            token = doc.get("access_token") if isinstance(doc, dict) else None
            try:
                _header, claims = h1.decode_jwt(token)
            except Exception:
                claims = {}
            authority = claims.get("authority_id")
            act = claims.get("act")
            checks = {
                "sub": claims.get("sub") == self.h2.users["user"],
                "aud": claims.get("aud") in ([target_audience], target_audience),
                "act": isinstance(act, dict) and act.get("sub") == self.names["workloads"]["sibling"]["workloadRef"],
                "source_session": claims.get("subject_sid") == self.env.variables.get("p1_sid"),
                "authority": isinstance(authority, str) and authority.startswith(f"workforce:{app}:"),
            }
            observed["claim_checks"] = checks
            observed["classification"] = "gap_present_cross_application_exchange_allowed"
            mismatches.extend(f"issued token {key} mismatch" for key, ok in checks.items() if not ok)
        elif status == 400 and isinstance(doc, dict) and doc.get("error") == "invalid_grant":
            observed["classification"] = "cross_application_exchange_rejected"
        else:
            observed["classification"] = "unexpected_response"
            mismatches.append("expected 200 with checked claims or 400 invalid_grant")
        self._record(h3.h3_case_result(CASE_ID, spec, observed, mismatches))
        self._check_5xx(CASE_ID, status)

    def cleanup_steps(self):
        steps = list(super().cleanup_steps())
        if self.extra_membership_id is not None:
            app = self.h2.apps["sibling"]
            mid = self.extra_membership_id
            path = f"/admin/tenants/{h2.TENANT}/applications/{app}/access/memberships/{mid}"
            steps.insert(0, ("remove_cross_app_membership",
                             lambda step: self._cleanup_call(step, "DELETE", path)))
        return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-5 G-07 isolated cross-application characterization")
    parser.add_argument("--package", required=True, choices=("h5-g07",))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 13):
        return 2
    if not args.execute:
        print(json.dumps({"event": "h5_plan", "package": PACKAGE, "mode": "dry",
                          "namespace": h2.NAMESPACE, "context": h2.CONTEXT,
                          "prefix_template": "p5x + secrets.token_hex(5)",
                          "h3_sha256": H3_SHA256, "case": CASE_ID,
                          "classification": {"200": "gap present, claims checked",
                                             "400 invalid_grant": "exchange rejected"},
                          "cleanup": "remove added sibling membership before H-3 cleanup"}))
        return 0
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt(f"signal {signum}")))
    return G07Runner().run()


if __name__ == "__main__":
    sys.exit(main())
