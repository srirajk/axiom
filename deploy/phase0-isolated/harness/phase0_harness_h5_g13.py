#!/opt/homebrew/bin/python3.13
"""H-5/G-13: characterize disposable user disable vs existing sessions/tokens."""

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
PACKAGE = "H-5/G-13"
EXTRA = ("H5-G13-D", "H5-G13-S", "H5-G13-I1", "H5-G13-I6", "H5-G13-X")


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


class G13Runner(h3.H3Runner):
    def __init__(self, *, prefix: str | None = None,
                 token_hex: Callable[[int], str] = secrets.token_hex, **kw: Any):
        super().__init__(expectations=copy.deepcopy(h3.H3_EXPECTATIONS),
                         prefix=prefix or "p5u" + token_hex(5), **kw)
        self.prior_ids = self.case_ids
        specs = {
            EXTRA[0]: ("disable only the fresh test user after token issuance", list(self.prior_ids)),
            EXTRA[1]: ("read whether the original root session remains ACTIVE", [EXTRA[0]]),
            EXTRA[2]: ("classify introspection of the issued human token", [EXTRA[0]]),
            EXTRA[3]: ("classify introspection of the issued resource token", [EXTRA[0]]),
            EXTRA[4]: ("classify broker exchange using the issued gateway token", [EXTRA[0]]),
        }
        for cid, (description, deps) in specs.items():
            self.expectations["order"].append(cid)
            self.expectations["cases"][cid] = {"class": "user_disable_characterization",
                                               "kind": "user_disable_check", "depends": deps,
                                               "description": description}
        self.case_ids = tuple(self.expectations["order"])

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

    def _disable(self, cid: str, spec: dict) -> None:
        user = self.h2.users.get("user")
        if not h2._safe_id(user):
            self._record(h3.h3_case_result(cid, spec, {}, ["test user unavailable"])); return
        status, raw = self.request("PUT", f"/users/{user}", bearer=self.admin_token,
                                   json_body={"isActive": False}, abort_on_5xx=False)
        doc = h2.parse_json(raw)
        ok = status == 200 and isinstance(doc, dict) and doc.get("id") == user \
            and doc.get("isActive") is False
        self._record(h3.h3_case_result(cid, spec, {"status": status, "returned_inactive": ok},
                                       [] if ok else ["test user disable not confirmed"]))
        self._check_5xx(cid, status)

    def _session_state(self, cid: str, spec: dict) -> None:
        root = self.env.sids.get("H3-C1")
        user = self.h2.users.get("user")
        if not h2._safe_id(root) or not h2._safe_id(user):
            self._record(h3.h3_case_result(cid, spec, {}, ["root session or test user unavailable"])); return
        query = urllib.parse.urlencode({"principalId": user, "status": "ACTIVE", "size": 100})
        status, raw = self.request("GET", f"/admin/tenants/{h2.TENANT}/sessions?{query}",
                                   bearer=self.admin_token, abort_on_5xx=False)
        doc = h2.parse_json(raw)
        items = doc.get("content") if isinstance(doc, dict) else doc
        total = doc.get("totalElements") if isinstance(doc, dict) else None
        valid = status == 200 and isinstance(items, list) \
            and not (isinstance(total, int) and total > len(items))
        matches = [it for it in items if isinstance(it, dict) and it.get("id") == root
                   and it.get("principalId") == user and it.get("status") == "ACTIVE"] if valid else []
        valid = valid and len(matches) <= 1
        self._record(h3.h3_case_result(cid, spec,
                                       {"status": status, "root_session_active": bool(matches)},
                                       [] if valid else ["session list malformed or incomplete"]))
        self._check_5xx(cid, status)

    def _introspect_state(self, cid: str, spec: dict, token_case: str) -> None:
        token = self.tokens.get(token_case)
        who = self._introspector()
        if token is None or who is None:
            self._record(h3.h3_case_result(cid, spec, {}, ["token or introspector unavailable"])); return
        status, _headers, raw = self._introspect(token, who)
        doc = h2.parse_json(raw)
        active = doc.get("active") if isinstance(doc, dict) else None
        valid = status == 200 and type(active) is bool \
            and (active or set(doc) == {"active"})
        if active is True:
            valid = valid and doc.get("sub") == self.h2.users["user"]
        self._record(h3.h3_case_result(cid, spec,
                                       {"status": status, "active": active, "source_case": token_case},
                                       [] if valid else ["introspection response malformed"]))
        self._check_5xx(cid, status)

    def _exchange_state(self, cid: str, spec: dict) -> None:
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
        issued = isinstance(doc, dict) and isinstance(doc.get("access_token"), str)
        valid = False
        if status == 200 and issued:
            try:
                _header, claims = h1.decode_jwt(doc["access_token"])
                valid = claims.get("sub") == self.h2.users["user"] \
                    and claims.get("aud") in ([form["audience"]], form["audience"])
            except Exception:
                pass
        elif status == 400 and error in ("invalid_grant", "invalid_target") and not issued:
            valid = True
        self._record(h3.h3_case_result(cid, spec,
                                       {"status": status, "error": error,
                                        "exchange_issued": bool(status == 200 and issued)},
                                       [] if valid else ["exchange response malformed or claims mismatched"]))
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
                self._disable(cid, spec)
            elif cid == EXTRA[1]:
                self._session_state(cid, spec)
            elif cid == EXTRA[2]:
                self._introspect_state(cid, spec, "H3-C1")
            elif cid == EXTRA[3]:
                self._introspect_state(cid, spec, "H3-C6")
            else:
                self._exchange_state(cid, spec)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-5 G-13 isolated user-disable characterization")
    parser.add_argument("--package", required=True, choices=("h5-g13",))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 13):
        return 2
    if not args.execute:
        print(json.dumps({"event": "h5_plan", "package": PACKAGE, "mode": "dry",
                          "namespace": h2.NAMESPACE, "context": h2.CONTEXT,
                          "prefix_template": "p5u + secrets.token_hex(5)",
                          "h3_sha256": H3_SHA256, "cases": EXTRA,
                          "cleanup": "existing H-3 cleanup revokes the test user's sessions and soft-deletes it"}))
        return 0
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt(f"signal {signum}")))
    return G13Runner().run()


if __name__ == "__main__":
    sys.exit(main())
