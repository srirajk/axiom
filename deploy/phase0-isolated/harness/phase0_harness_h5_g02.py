#!/opt/homebrew/bin/python3.13
"""H-5/G-02: classify broker-before-workload registration using disposable identities.

Both 201 (gap present) and 409 (gap absent) are valid *observations*; neither is
silently treated as a production policy decision. H-4 provides the isolated
setup, preflights, functional controls and cleanup. No call is made without
--execute. Only the new test-prefix broker client is used.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import signal
import sys
from typing import Any, Callable

HERE = os.path.dirname(os.path.abspath(__file__))
H4_PATH = os.path.join(HERE, "phase0_harness_h4.py")
H4_SHA256 = "0cb6709ca31a50efe7a52664c08f555083d5e7954eaf2b3a36bb32eb35232634"


def load_h4() -> Any:
    with open(H4_PATH, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != H4_SHA256:
            raise ImportError("H-4 source differs from reviewed version")
    existing = sys.modules.get("phase0_harness_h4")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(H4_PATH):
            raise ImportError("H-4 imported from an unexpected path")
        return existing
    spec = importlib.util.spec_from_file_location("phase0_harness_h4", H4_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load H-4 source")
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase0_harness_h4"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("phase0_harness_h4", None)
        raise
    return module


h4 = load_h4()
h3, h2, h1 = h4.h3, h4.h2, h4.h1
PACKAGE = "H-5/G-02"
CASE_ID = "H5-G02"


class G02Runner(h4.H4Runner):
    def __init__(self, *, prefix: str | None = None,
                 token_hex: Callable[[int], str] = secrets.token_hex, **kw: Any):
        super().__init__(prefix=prefix or "p5g" + token_hex(5), **kw)
        self.prior_ids = self.case_ids
        self.expectations["order"].append(CASE_ID)
        self.expectations["cases"][CASE_ID] = {
            "class": "registration_order_characterization", "kind": "broker_then_workload",
            "depends": list(self.prior_ids),
            "description": "try registering the fresh test broker client as a workload; classify 201 vs 409",
        }
        self.case_ids = tuple(self.expectations["order"])
        self.extra_workload_id: str | None = None

    def emit(self, event: dict) -> None:
        ev = dict(event)
        step = ev.get("step")
        if isinstance(step, str):
            match = h3._SESSION_STEP.match(step)
            if match:
                ev["step"] = f"{match.group(1)}:{h3.sha12(match.group(2))}"
        name = str(ev.get("event", ""))
        for prefix in ("h4_", "h3_", "h2_", "h5_"):
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
            h4.H4Runner.run_cases(self)
        finally:
            self.case_ids = all_ids
        spec = self.expectations["cases"][CASE_ID]
        blocked = [dep for dep in spec["depends"] if self.results.get(dep, {}).get("result") != "pass"]
        if blocked:
            self._record(h2.skipped_case(CASE_ID, spec, "prerequisite failed"))
            return
        client = self.names["clients"]["broker"]["clientId"]
        ref = f"agent:{self.prefix}-broker-after:test"
        path = f"/admin/tenants/{h2.TENANT}/ciam/agent-workloads"
        status, raw = self.request("POST", path, bearer=self.admin_token,
                                   json_body={"workloadRef": ref, "name": ref, "oauthClientId": client},
                                   abort_on_5xx=False)
        self._check_5xx(CASE_ID, status)
        doc = h2.parse_json(raw)
        observed = {"status": status, "client": client}
        mismatches: list[str] = []
        if status == 201:
            wid = doc.get("id") if isinstance(doc, dict) else None
            if not h2._safe_id(wid):
                self.cleanup_incomplete = True
                mismatches.append("created workload id missing or unsafe; manual cleanup required")
            else:
                self.extra_workload_id = str(wid)
            observed["classification"] = "gap_present_broker_then_workload_allowed"
        elif status == 409:
            observed["classification"] = "registration_rejected"
        else:
            observed["classification"] = "unexpected_response"
            mismatches.append("expected 201 or 409 from same-client registration")
        self._record(h3.h3_case_result(CASE_ID, spec, observed, mismatches))

    def cleanup_steps(self):
        steps = list(super().cleanup_steps())
        if self.extra_workload_id is not None:
            wid = self.extra_workload_id
            path = f"/admin/tenants/{h2.TENANT}/ciam/agent-workloads/{wid}/revoke"
            steps.insert(0, ("revoke_workload:broker_after",
                             lambda step: self._cleanup_call(step, "POST", path)))
        return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-5 G-02 isolated order characterization")
    parser.add_argument("--package", required=True, choices=("h5-g02",))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 13):
        return 2
    if not args.execute:
        print(json.dumps({"event": "h5_plan", "package": PACKAGE, "mode": "dry", "namespace": h2.NAMESPACE,
                          "context": h2.CONTEXT, "prefix_template": "p5g + secrets.token_hex(5)",
                          "h4_sha256": H4_SHA256, "case": CASE_ID,
                          "classification": {"201": "gap present", "409": "registration rejected"},
                          "cleanup": "revoke any extra workload before H-4 cleanup"}))
        return 0
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt(f"signal {signum}")))
    return G02Runner().run()


if __name__ == "__main__":
    sys.exit(main())
