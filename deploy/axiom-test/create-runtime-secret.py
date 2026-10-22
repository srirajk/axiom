#!/usr/bin/env python3
"""Create three fresh operator-owned runtime credentials for a disposable local Axiom estate.

No credential is written to disk, printed, placed in a command argument, or stored in a Helm release.
The generated administrator password is intentionally not revealed; use a controlled password-reset
flow if an interactive administrator sign-in is needed later.
"""

import base64
import argparse
import json
import secrets
import subprocess

CONTEXT = "docker-desktop"
NAME = "axiom-runtime"


def run(*arguments: str, input_data: bytes | None = None) -> None:
    subprocess.run(["kubectl", "--context", CONTEXT, *arguments], input=input_data, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default="axiom-test", choices=("axiom-test", "axiom"))
    args = parser.parse_args()
    namespace_name = args.namespace
    namespace = subprocess.run(
        ["kubectl", "--context", CONTEXT, "get", "namespace", namespace_name, "-o", "name"],
        capture_output=True,
        text=True,
        check=True,
    )
    if namespace.stdout.strip() != f"namespace/{namespace_name}":
        raise SystemExit("Unexpected namespace target")
    existing = subprocess.run(
        ["kubectl", "--context", CONTEXT, "get", "secret", NAME, "-n", namespace_name],
        capture_output=True,
    )
    if existing.returncode == 0:
        raise SystemExit(f"{namespace_name}/{NAME} already exists; refusing to replace credentials")
    credentials = {
        "spring.datasource.password": secrets.token_urlsafe(36),
        "iam.secrets.master-key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "axiom.bootstrap.admin-password": secrets.token_urlsafe(36),
    }
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": NAME, "namespace": namespace_name},
        "type": "Opaque",
        "data": {
            key: base64.b64encode(value.encode("utf-8")).decode("ascii")
            for key, value in credentials.items()
        },
    }
    run("create", "-f", "-", input_data=json.dumps(manifest).encode("utf-8"))
    print(f"Created {namespace_name}/{NAME} with fresh credentials; no value was displayed.")


if __name__ == "__main__":
    main()
