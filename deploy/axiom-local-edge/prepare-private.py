#!/usr/bin/env python3
"""Create and install private credentials for the disposable Docker Desktop Axiom estate.

The local files are plaintext, owner-only, and Git-ignored. Back them up securely if
this estate must survive a cluster reset. Never use this helper for production.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import hmac


ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"
CERTS = PRIVATE / "certs"
PASSWORDS = PRIVATE / "passwords"
CONTEXT = "docker-desktop"


def run(*command: str, input_data: bytes | None = None) -> None:
    subprocess.run(command, input=input_data, check=True, stdout=subprocess.DEVNULL)


def write_private(path: Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(value)
    path.chmod(0o600)


def generate_tls(stem: str, hostname: str) -> None:
    key = CERTS / f"{stem}.key"
    cert = CERTS / f"{stem}.crt"
    request = CERTS / f"{stem}.csr"
    run(
        "openssl", "req", "-new", "-newkey", "rsa:3072", "-sha256", "-nodes",
        "-subj", f"/CN={hostname}/O=Axiom Local Test",
        "-keyout", str(key), "-out", str(request),
    )
    extensions = (f"basicConstraints=critical,CA:FALSE\n"
                  f"keyUsage=critical,digitalSignature,keyEncipherment\n"
                  f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{hostname}\n")
    run("openssl", "x509", "-req", "-in", str(request),
        "-CA", str(CERTS / "local-ca.crt"), "-CAkey", str(CERTS / "local-ca.key"),
        "-CAcreateserial", "-days", "30", "-sha256", "-extfile", "/dev/stdin",
        "-out", str(cert), input_data=extensions.encode("ascii"))
    request.unlink()
    key.chmod(0o600)
    cert.chmod(0o600)


def generate_local_ca() -> None:
    key = CERTS / "local-ca.key"
    cert = CERTS / "local-ca.crt"
    run("openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
        "-days", "365", "-subj", "/CN=Axiom Disposable Local CA/O=Axiom Local Test",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout", str(key), "-out", str(cert))
    key.chmod(0o600)
    cert.chmod(0o600)


def generate() -> None:
    if PRIVATE.exists() or PRIVATE.is_symlink():
        raise SystemExit(f"{PRIVATE} already exists; refusing to replace private material")
    PRIVATE.mkdir(mode=0o700)
    CERTS.mkdir(mode=0o700)
    PASSWORDS.mkdir(mode=0o700)
    write_private(PASSWORDS / "axiom-admin-username", "admin")
    write_private(PASSWORDS / "axiom-admin-password", secrets.token_urlsafe(36))
    write_private(PASSWORDS / "postgres-password", secrets.token_urlsafe(36))
    write_private(PASSWORDS / "axiom-master-key", base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
    generate_local_ca()
    generate_tls("axiom-identity", "identity.meridian.com")
    generate_tls("axiom-admin", "identity-admin.meridian.com")
    signer = ROOT.parent / "helm" / "axiom" / "scripts" / "create-signing-secret.py"
    run(sys.executable, str(signer), "--output-dir", str(CERTS))
    for name in ("signing-key.json", "jwks.json"):
        (CERTS / name).chmod(0o600)
    print(f"Created private files under {PRIVATE}; no passwords or keys displayed.")


def renew_tls() -> None:
    """Replace only local edge TLS material; preserve old certificates and all Axiom credentials."""
    if not PRIVATE.is_dir() or PRIVATE.is_symlink() or not CERTS.is_dir() or CERTS.is_symlink():
        raise SystemExit("Missing safe local private/certs directory")
    names = ("local-ca.crt", "local-ca.key", "local-ca.srl", "axiom-identity.crt", "axiom-identity.key",
             "axiom-admin.crt", "axiom-admin.key")
    for name in names:
        path = CERTS / name
        if path.exists() and (not path.is_file() or path.is_symlink()):
            raise SystemExit(f"Refusing non-regular TLS file: {path}")
    backup = CERTS / ("previous-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                      + "-" + secrets.token_hex(3))
    backup.mkdir(mode=0o700)
    moved: list[str] = []
    try:
        for name in names:
            source = CERTS / name
            if source.exists():
                source.rename(backup / name)
                moved.append(name)
        generate_local_ca()
        generate_tls("axiom-identity", "identity.meridian.com")
        generate_tls("axiom-admin", "identity-admin.meridian.com")
        verify_tls()
    except BaseException:
        for name in names:
            current = CERTS / name
            if current.exists():
                current.unlink()
        for name in moved:
            (backup / name).rename(CERTS / name)
        backup.rmdir()
        raise
    print(f"Replaced local TLS material; prior files retained under {backup}; signing key and passwords unchanged.")


def verify_tls() -> None:
    ca = CERTS / "local-ca.crt"
    if not ca.is_file() or ca.is_symlink():
        raise SystemExit("Missing regular local CA certificate")
    for stem, hostname in (("axiom-identity", "identity.meridian.com"),
                           ("axiom-admin", "identity-admin.meridian.com")):
        cert = CERTS / f"{stem}.crt"
        key = CERTS / f"{stem}.key"
        if any(not path.is_file() or path.is_symlink() for path in (cert, key)):
            raise SystemExit(f"Missing regular TLS leaf files for {stem}")
        run("openssl", "verify", "-CAfile", str(ca), str(cert))
        details = subprocess.run(("openssl", "x509", "-in", str(cert), "-noout", "-text"),
                                 check=True, capture_output=True, text=True).stdout
        if "CA:FALSE" not in details or "TLS Web Server Authentication" not in details \
                or f"DNS:{hostname}" not in details or "CA:TRUE" in details:
            raise SystemExit(f"Invalid server leaf certificate: {stem}")


def kubectl(*arguments: str, input_data: bytes | None = None) -> None:
    run("kubectl", "--context", CONTEXT, *arguments, input_data=input_data)


def require_namespace(name: str) -> None:
    result = subprocess.run(
        ["kubectl", "--context", CONTEXT, "get", "namespace", name, "-o", "name"],
        capture_output=True, text=True, check=True,
    )
    if result.stdout.strip() != f"namespace/{name}":
        raise SystemExit(f"Unexpected namespace result for {name}")


def create_secret(namespace: str, name: str, files: dict[str, Path], kind: str, immutable: bool = False) -> None:
    manifest = {
        "apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": namespace},
        "type": kind, "data": {
            key: base64.b64encode(path.read_bytes()).decode("ascii") for key, path in files.items()
        },
    }
    if immutable:
        manifest["immutable"] = True
    kubectl("create", "-f", "-", input_data=json.dumps(manifest).encode("utf-8"))


def secret_matches(existing: dict, files: dict[str, Path], kind: str, immutable: bool = False) -> bool:
    """Compare Secret contents without displaying private values or accepting extra data keys."""
    expected = {key: base64.b64encode(path.read_bytes()).decode("ascii") for key, path in files.items()}
    actual = existing.get("data") or {}
    return (existing.get("type") == kind
            and bool(existing.get("immutable", False)) == immutable
            and actual.keys() == expected.keys()
            and all(hmac.compare_digest(actual[key], value) for key, value in expected.items()))


def ensure_secret(namespace: str, name: str, files: dict[str, Path], kind: str,
                  immutable: bool = False) -> None:
    result = subprocess.run(
        ["kubectl", "--context", CONTEXT, "-n", namespace, "get", "secret", name,
         "-o", "json", "--ignore-not-found"], capture_output=True, text=True, check=True,
    )
    if result.stdout.strip():
        if not secret_matches(json.loads(result.stdout), files, kind, immutable):
            raise SystemExit(f"{namespace}/{name} differs from local private files; refusing replacement")
        print(f"Retained matching Secret {namespace}/{name}.")
    else:
        create_secret(namespace, name, files, kind, immutable)
        print(f"Created Secret {namespace}/{name}.")


def install() -> None:
    if not PRIVATE.is_dir() or PRIVATE.is_symlink():
        raise SystemExit(f"Missing safe local directory: {PRIVATE}")
    if subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True,
                      check=True).stdout.strip() != CONTEXT:
        raise SystemExit("Refusing Secret installation outside docker-desktop")
    verify_tls()
    for namespace in ("axiom", "gateway-demo"):
        require_namespace(namespace)
    expected = (
        ("axiom", "axiom-runtime"), ("axiom", "axiom-signing-key"),
        ("gateway-demo", "axiom-identity-tls"), ("gateway-demo", "axiom-admin-tls"),
    )
    for namespace, name in expected:
        found = subprocess.run(
            ["kubectl", "--context", CONTEXT, "get", "secret", name, "-n", namespace],
            capture_output=True,
        )
        if found.returncode == 0:
            raise SystemExit(f"{namespace}/{name} already exists; refusing to replace credentials")
    create_secret("axiom", "axiom-runtime", {
        "spring.datasource.password": PASSWORDS / "postgres-password",
        "iam.secrets.master-key": PASSWORDS / "axiom-master-key",
        "axiom.bootstrap.admin-password": PASSWORDS / "axiom-admin-password",
    }, "Opaque")
    create_secret("axiom", "axiom-signing-key", {
        "signing-key.json": CERTS / "signing-key.json",
        "jwks.json": CERTS / "jwks.json",
    }, "Opaque", immutable=True)
    for stem, secret_name in (("axiom-identity", "axiom-identity-tls"),
                              ("axiom-admin", "axiom-admin-tls")):
        create_secret("gateway-demo", secret_name, {
            "tls.crt": CERTS / f"{stem}.crt",
            "tls.key": CERTS / f"{stem}.key",
        }, "kubernetes.io/tls")
    print("Installed Axiom runtime, signing, and both TLS Secrets; no values displayed.")


def ensure() -> None:
    """Resume a partial local install, but never overwrite mismatched credentials."""
    if not PRIVATE.is_dir() or PRIVATE.is_symlink():
        raise SystemExit(f"Missing safe local directory: {PRIVATE}")
    if subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True,
                      check=True).stdout.strip() != CONTEXT:
        raise SystemExit("Refusing Secret installation outside docker-desktop")
    verify_tls()
    for namespace in ("axiom", "gateway-demo"):
        require_namespace(namespace)
    ensure_secret("axiom", "axiom-runtime", {
        "spring.datasource.password": PASSWORDS / "postgres-password",
        "iam.secrets.master-key": PASSWORDS / "axiom-master-key",
        "axiom.bootstrap.admin-password": PASSWORDS / "axiom-admin-password",
    }, "Opaque")
    ensure_secret("axiom", "axiom-signing-key", {
        "signing-key.json": CERTS / "signing-key.json",
        "jwks.json": CERTS / "jwks.json",
    }, "Opaque", immutable=True)
    for stem, secret_name in (("axiom-identity", "axiom-identity-tls"),
                              ("axiom-admin", "axiom-admin-tls")):
        ensure_secret("gateway-demo", secret_name, {
            "tls.crt": CERTS / f"{stem}.crt",
            "tls.key": CERTS / f"{stem}.key",
        }, "kubernetes.io/tls")
    print("Axiom Secrets match local private material; no values displayed.")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("generate", "renew-tls", "install", "ensure"))
    selected = parser.parse_args().action
    if selected == "generate":
        generate()
    elif selected == "renew-tls":
        renew_tls()
    elif selected == "install":
        install()
    else:
        ensure()
