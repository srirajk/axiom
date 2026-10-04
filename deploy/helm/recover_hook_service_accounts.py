#!/usr/bin/env python3
"""Exact-target recovery for the Axiom chart's hook ServiceAccounts after a FAILED install or upgrade.

On success, Helm removes the bootstrap and preflight ServiceAccounts itself (hook-delete-policy hook-succeeded runs
after every hook of the phase). A failed pre-install/pre-upgrade phase leaves them, and `helm uninstall` never
deletes hook resources, so an account carrying a cloud-identity annotation could outlive the release.

This tool targets only the two exact names the chart renders for one release, never a label selector, and deletes a
ServiceAccount only when all of these hold:
  * its labels say it is this release's Helm-managed bootstrap or preflight account;
  * it is a pre-install/pre-upgrade hook resource;
  * no running pod and no active Job in the namespace uses it.
It never reads Secrets or Helm release storage. Default is a read-only plan; --execute deletes.

    python3 deploy/helm/recover_hook_service_accounts.py -n axiom --release axiom            # plan
    python3 deploy/helm/recover_hook_service_accounts.py -n axiom --release axiom --execute  # delete
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

CHART_NAME = "axiom"
COMPONENTS = ("bootstrap", "preflight")
TERMINAL_POD_PHASES = {"Succeeded", "Failed"}


class RecoveryError(RuntimeError):
    pass


def fullname(release: str, fullname_override: str = "", name_override: str = "") -> str:
    """Mirror of the chart's axiom.fullname helper."""
    if fullname_override:
        return fullname_override[:63].rstrip("-")
    name = (name_override or CHART_NAME)[:63].rstrip("-")
    if name in release:
        return release[:63].rstrip("-")
    return f"{release}-{name}"[:63].rstrip("-")


def kubectl_json(namespace: str, *args: str) -> dict | None:
    """Read-only kubectl get; None when the object does not exist."""
    result = subprocess.run(["kubectl", "get", *args, "-n", namespace, "-o", "json", "--ignore-not-found"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RecoveryError(f"kubectl get {' '.join(args)} failed: {result.stderr.strip()[:200]}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def users_of(namespace: str, name: str) -> list[str]:
    users = []
    pods = kubectl_json(namespace, "pods") or {"items": []}
    for pod in pods["items"]:
        if pod["spec"].get("serviceAccountName") == name and pod.get("status", {}).get("phase") not in TERMINAL_POD_PHASES:
            users.append(f"pod/{pod['metadata']['name']}")
    jobs = kubectl_json(namespace, "jobs") or {"items": []}
    for job in jobs["items"]:
        if job["spec"]["template"]["spec"].get("serviceAccountName") == name and job.get("status", {}).get("active"):
            users.append(f"job/{job['metadata']['name']}")
    return users


def assess(namespace: str, release: str, name: str, component: str) -> dict:
    account = kubectl_json(namespace, "serviceaccount", name)
    if account is None:
        return {"name": name, "action": "none", "reason": "absent"}
    meta = account["metadata"]
    labels = meta.get("labels") or {}
    annotations = meta.get("annotations") or {}
    expected = {"app.kubernetes.io/instance": release, "app.kubernetes.io/managed-by": "Helm",
                "app.kubernetes.io/name": CHART_NAME, "app.kubernetes.io/component": component}
    mismatched = sorted(k for k, v in expected.items() if labels.get(k) != v)
    hooks = {h.strip() for h in annotations.get("helm.sh/hook", "").split(",") if h.strip()}
    record = {"name": name, "uid": meta.get("uid"),
              # Annotation keys only: values (for example a cloud role) are not printed.
              "extra_annotation_keys": sorted(k for k in annotations if not k.startswith("helm.sh/"))}
    if mismatched:
        return {**record, "action": "refuse", "reason": f"labels do not identify this release's {component} "
                                                       f"account: {', '.join(mismatched)}"}
    if not {"pre-install", "pre-upgrade"} & hooks:
        return {**record, "action": "refuse", "reason": "not a pre-install/pre-upgrade hook resource"}
    in_use = users_of(namespace, name)
    if in_use:
        return {**record, "action": "refuse", "reason": "in use by " + ", ".join(in_use)}
    return {**record, "action": "delete"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-n", "--namespace", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--fullname-override", default="")
    parser.add_argument("--name-override", default="")
    parser.add_argument("--bootstrap-name", default="", help="serviceAccount.bootstrap.name, if set in values")
    parser.add_argument("--preflight-name", default="", help="serviceAccount.preflight.name, if set in values")
    parser.add_argument("--execute", action="store_true", help="delete the accounts the plan marks for deletion")
    args = parser.parse_args(argv)

    base = fullname(args.release, args.fullname_override, args.name_override)
    targets = {"bootstrap": args.bootstrap_name or f"{base}-bootstrap",
               "preflight": args.preflight_name or f"{base}-preflight"}
    try:
        plan = [assess(args.namespace, args.release, name, component) for component, name in targets.items()]
    except RecoveryError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps({"namespace": args.namespace, "release": args.release, "execute": args.execute, "plan": plan}))
    if any(item["action"] == "refuse" for item in plan):
        return 2
    if not args.execute:
        return 0
    for item in plan:
        if item["action"] != "delete":
            continue
        result = subprocess.run(["kubectl", "delete", "serviceaccount", item["name"], "-n", args.namespace,
                                 "--wait=true"], capture_output=True, text=True)
        if result.returncode != 0:
            print(json.dumps({"deleted": False, "name": item["name"], "error": result.stderr.strip()[:200]}),
                  file=sys.stderr)
            return 2
        if kubectl_json(args.namespace, "serviceaccount", item["name"]) is not None:
            print(json.dumps({"deleted": False, "name": item["name"], "error": "still present"}), file=sys.stderr)
            return 2
        print(json.dumps({"deleted": True, "name": item["name"], "uid": item["uid"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
