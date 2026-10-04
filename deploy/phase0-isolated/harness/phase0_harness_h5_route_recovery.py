#!/opt/homebrew/bin/python3.13
"""TEST-X-only route replacement drill after H-5/G-12 revocation."""

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
G12_PATH = os.path.join(HERE, "phase0_harness_h5_g12.py")
G12_SHA256 = "48175c0d3cbccb8193c9c60576261c7f31cc0ac627e86a9643d9e4d8c6a23256"
PACKAGE = "H-5/route-recovery"
EXTRA = ("H5-RR-C", "H5-RR-X", "H5-RR-I")


def load_g12() -> Any:
    with open(G12_PATH, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != G12_SHA256:
            raise ImportError("G-12 source differs from reviewed version")
    existing = sys.modules.get("phase0_harness_h5_g12")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(G12_PATH):
            raise ImportError("G-12 imported from unexpected path")
        return existing
    spec = importlib.util.spec_from_file_location("phase0_harness_h5_g12", G12_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load G-12")
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase0_harness_h5_g12"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("phase0_harness_h5_g12", None)
        raise
    return module


g12 = load_g12()
h3, h2, h1 = g12.h3, g12.h2, g12.h1


class RouteRecoveryRunner(g12.G12Runner):
    def __init__(self, *, prefix: str | None = None,
                 token_hex: Callable[[int], str] = secrets.token_hex, **kw: Any):
        super().__init__(prefix=prefix or "p5q" + token_hex(5), **kw)
        self.g12_ids = self.case_ids
        specs = {
            EXTRA[0]: ("create a replacement R4 route with a new authority ID", [g12.EXTRA[0]]),
            EXTRA[1]: ("broker obtains a new resource token through the replacement route", [EXTRA[0]]),
            EXTRA[2]: ("new token active while the old revoked-route token stays inactive", [EXTRA[1]]),
        }
        for cid, (description, deps) in specs.items():
            self.expectations["order"].append(cid)
            self.expectations["cases"][cid] = {"class": "route_recovery_characterization",
                                               "kind": "route_recovery_check", "depends": deps,
                                               "description": description}
        self.case_ids = tuple(self.expectations["order"])
        self.replacement_id: str | None = None
        self.new_token: h2.SensitiveValue | None = None

    def emit(self, event: dict) -> None:
        ev = dict(event)
        step = ev.get("step")
        if isinstance(step, str):
            match = h3._SESSION_STEP.match(step)
            if match:
                ev["step"] = f"{match.group(1)}:{h3.sha12(match.group(2))}"
        name = str(ev.get("event", ""))
        for prefix in ("h5_", "h3_", "h2_"):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        ev["event"] = "h5_" + name
        ev["package"] = PACKAGE
        h1.Runner.emit(self, ev)

    def _create(self, cid: str, spec: dict) -> None:
        r = self.names["routes"]["R4"]
        path = f"/admin/tenants/{h2.TENANT}/agent-exchange/routes"
        body = {"sourceWorkloadId": self.h2.workloads[r["source"]],
                "destinationType": r["destinationType"], "destinationWorkloadId": None,
                "audience": self.names["applications"][r["audience_app"]]["audience"],
                "scopes": [h2.SCOPE], "purpose": h2.ROUTE_PURPOSE,
                "expiresAt": h1.iso_utc(self.now() + 3600)}
        status, raw = self.request("POST", path, bearer=self.admin_token,
                                   json_body=body, abort_on_5xx=False)
        self._check_5xx(cid, status)
        doc = h2.parse_json(raw)
        rid = doc.get("id") if isinstance(doc, dict) else None
        valid = status == 201 and h2._safe_id(rid) and rid != self.h2.routes["R4"]
        if status == 201 and h2._safe_id(rid):
            self.replacement_id = str(rid)
        elif status == 201:
            self.cleanup_incomplete = True
        self._record(h3.h3_case_result(cid, spec,
                                       {"status": status, "new_authority_id": bool(valid)},
                                       [] if valid else ["replacement route creation not confirmed"]))

    def _exchange(self, cid: str, spec: dict) -> None:
        old_subject = self.tokens["H3-C5"]
        secret = self.client_secrets["broker"]
        audience = self.names["applications"]["tool"]["audience"]
        form = {"grant_type": h2.TOKEN_EXCHANGE_GRANT, "subject_token": old_subject.reveal(),
                "subject_token_type": h2.ACCESS_TOKEN_TYPE, "requested_token_type": h2.ACCESS_TOKEN_TYPE,
                "audience": audience, "scope": h2.SCOPE}
        status, raw = self.request("POST", "/oauth/token", form=form,
                                   basic=(self.names["clients"]["broker"]["clientId"], secret),
                                   abort_on_5xx=False)
        self._register_body_tokens(raw)
        doc = h2.parse_json(raw)
        token = doc.get("access_token") if isinstance(doc, dict) else None
        try:
            _header, claims = h1.decode_jwt(token)
        except Exception:
            claims = {}
        valid = status == 200 and isinstance(token, str) \
            and claims.get("authority_id") == self.replacement_id \
            and claims.get("sub") == self.h2.users["user"] \
            and claims.get("aud") in ([audience], audience)
        if valid:
            self.new_token = self._sensitive(token)
        self._record(h3.h3_case_result(cid, spec, {"status": status,
                                                 "authority_is_replacement": bool(valid)},
                                       [] if valid else ["new token not bound to replacement route"]))
        self._check_5xx(cid, status)

    def _introspect_pair(self, cid: str, spec: dict) -> None:
        who = self._introspector()
        if who is None or self.new_token is None:
            self._record(h3.h3_case_result(cid, spec, {}, ["introspection inputs unavailable"])); return
        states = {}
        for label, token in (("old", self.tokens["H3-C6"]), ("new", self.new_token)):
            status, _headers, raw = self._introspect(token, who)
            doc = h2.parse_json(raw)
            states[label] = (status, doc)
            self._check_5xx(cid, status)
        old_status, old = states["old"]
        new_status, new = states["new"]
        valid = old_status == new_status == 200 and isinstance(old, dict) and old == {"active": False} \
            and isinstance(new, dict) and new.get("active") is True \
            and new.get("authority_id") == self.replacement_id
        self._record(h3.h3_case_result(cid, spec,
                                       {"old_status": old_status, "old_active": old.get("active") if isinstance(old, dict) else None,
                                        "new_status": new_status, "new_active": new.get("active") if isinstance(new, dict) else None,
                                        "new_authority_is_replacement": bool(isinstance(new, dict) and new.get("authority_id") == self.replacement_id)},
                                       [] if valid else ["old/new token introspection did not separate authority IDs"]))

    def run_cases(self) -> None:
        all_ids = self.case_ids
        try:
            self.case_ids = self.g12_ids
            g12.G12Runner.run_cases(self)
        finally:
            self.case_ids = all_ids
        for cid in EXTRA:
            spec = self.expectations["cases"][cid]
            if any(self.results.get(dep, {}).get("result") != "pass" for dep in spec["depends"]):
                self._record(h2.skipped_case(cid, spec, "prerequisite failed")); continue
            if cid == EXTRA[0]:
                self._create(cid, spec)
            elif cid == EXTRA[1]:
                self._exchange(cid, spec)
            else:
                self._introspect_pair(cid, spec)

    def cleanup_steps(self):
        steps = list(super().cleanup_steps())
        if self.replacement_id is not None:
            path = f"/admin/tenants/{h2.TENANT}/agent-exchange/routes/{self.replacement_id}/revoke"
            steps.insert(0, ("revoke_replacement_route",
                             lambda step: self._cleanup_call(step, "POST", path)))
        return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TEST-X-only route replacement drill")
    parser.add_argument("--package", required=True, choices=("route-recovery",))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 13):
        return 2
    if not args.execute:
        print(json.dumps({"event": "h5_plan", "package": PACKAGE, "mode": "dry",
                          "namespace": h2.NAMESPACE, "context": h2.CONTEXT,
                          "prefix_template": "p5q + secrets.token_hex(5)",
                          "g12_sha256": G12_SHA256, "cases": EXTRA,
                          "cleanup": "revoke replacement route, then normal G-12 cleanup"}))
        return 0
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt(f"signal {signum}")))
    return RouteRecoveryRunner().run()


if __name__ == "__main__":
    sys.exit(main())
