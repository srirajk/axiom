#!/usr/bin/env python3
"""Attach local Axiom hostnames to the existing Docker Desktop Argus edge.

This is an optional local-cluster overlay. It leaves all existing Argus listeners
and Axiom's original private Gateway in place.
"""

import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = ["kubectl", "--context", "docker-desktop"]
EDGE = BASE + ["-n", "argus-edge"]


def run(args, *, input_text=None):
    return subprocess.run(args, input=input_text, text=True, check=True,
                          capture_output=True).stdout


def get_json(args):
    return json.loads(run(args + ["-o", "json"]))


def main():
    if run(["kubectl", "config", "current-context"]).strip() != "docker-desktop":
        raise SystemExit("Refusing to alter a cluster other than docker-desktop")

    gateway = get_json(EDGE + ["get", "gateway", "argus-edge"])
    existing = {listener["name"]: listener for listener in gateway["spec"]["listeners"]}
    expected = (
        ("axiom-identity", "identity.meridian.com", "axiom-identity-shared-edge-tls", "axiom-identity"),
        ("axiom-admin", "identity-admin.meridian.com", "axiom-admin-shared-edge-tls", "axiom-admin"),
    )
    for name, hostname, secret, _ in expected:
        current = existing.get(name)
        if current and (current.get("hostname") != hostname or current.get("port") != 8443
                        or current.get("protocol") != "HTTPS"
                        or current.get("tls", {}).get("certificateRefs", [{}])[0].get("name") != secret
                        or current.get("allowedRoutes", {}).get("namespaces", {}).get("selector", {})
                        .get("matchLabels", {}).get("kubernetes.io/metadata.name") != "gateway-demo"):
            raise SystemExit(f"Existing listener {name} differs; review it before proceeding")

    for _, _, secret, stem in expected:
        cert = HERE / "private" / "certs" / f"{stem}.crt"
        key = HERE / "private" / "certs" / f"{stem}.key"
        if not cert.is_file() or not key.is_file():
            raise SystemExit(f"Missing local TLS material for {stem}")
        manifest = run(EDGE + ["create", "secret", "tls", secret,
                               f"--cert={cert}", f"--key={key}", "--dry-run=client", "-o", "json"])
        proposed = json.loads(manifest)
        current = subprocess.run(EDGE + ["get", "secret", secret, "-o", "json"],
                                 text=True, capture_output=True)
        if current.returncode == 0:
            if json.loads(current.stdout).get("data") != proposed.get("data"):
                raise SystemExit(f"Existing TLS Secret {secret} differs; rotate it deliberately")
        else:
            run(EDGE + ["create", "-f", "-"], input_text=manifest)

    patch = [{"op": "test", "path": "/metadata/resourceVersion",
              "value": gateway["metadata"]["resourceVersion"]}]
    for name, hostname, secret, _ in expected:
        if name in existing:
            continue
        patch.append({"op": "add", "path": "/spec/listeners/-", "value": {
            "name": name, "hostname": hostname, "port": 8443, "protocol": "HTTPS",
            "tls": {"mode": "Terminate", "certificateRefs": [{"kind": "Secret", "name": secret}]},
            "allowedRoutes": {"kinds": [{"kind": "HTTPRoute"}], "namespaces": {
                "from": "Selector", "selector": {"matchLabels": {
                    "kubernetes.io/metadata.name": "gateway-demo"}}}}
        }})
    if len(patch) > 1:
        run(EDGE + ["patch", "gateway", "argus-edge", "--type=json", "-p", json.dumps(patch)])
    run(BASE + ["apply", "-f", str(HERE / "shared-edge-routes.yaml")])
    print("Axiom routes attached to the shared edge. Verify host port 8443 separately.")


if __name__ == "__main__":
    main()
