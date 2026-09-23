#!/usr/bin/env python3
"""Generate Axiom's bootstrap RSA JWK and optionally create an immutable Kubernetes Secret."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def b64url(value: int) -> str:
    width = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(width, "big")).rstrip(b"=").decode()


def read_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4:
        raise ValueError("unsupported DER length")
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def read_integer(data: bytes, offset: int) -> tuple[int, int]:
    if data[offset] != 0x02:
        raise ValueError("expected DER integer")
    length, offset = read_length(data, offset + 1)
    end = offset + length
    return int.from_bytes(data[offset:end], "big"), end


def parse_pkcs1(data: bytes) -> list[int]:
    if not data or data[0] != 0x30:
        raise ValueError("expected DER sequence")
    length, offset = read_length(data, 1)
    if offset + length != len(data):
        raise ValueError("invalid DER sequence length")
    values: list[int] = []
    while offset < len(data):
        value, offset = read_integer(data, offset)
        values.append(value)
    if len(values) != 9 or values[0] != 0:
        raise ValueError("expected an RSA PKCS#1 private key")
    return values


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default="axiom")
    parser.add_argument("--name", default="axiom-signing-key")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axiom-signing-") as temporary:
        work = Path(temporary)
        pem = work / "signing-key.pem"
        der = work / "signing-key.der"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(pem)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", str(pem), "-traditional", "-outform", "DER", "-out", str(der)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _, n, e, d, p, q, dp, dq, qi = parse_pkcs1(der.read_bytes())
        kid = str(uuid.uuid4())
        private_jwk = {
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": b64url(n), "e": b64url(e), "d": b64url(d),
            "p": b64url(p), "q": b64url(q), "dp": b64url(dp),
            "dq": b64url(dq), "qi": b64url(qi),
        }
        public_jwk = {key: private_jwk[key] for key in ("kty", "use", "alg", "kid", "n", "e")}

        output = args.output_dir or work
        output.mkdir(parents=True, exist_ok=True)
        private_path = output / "signing-key.json"
        public_path = output / "jwks.json"
        write_json(private_path, private_jwk)
        write_json(public_path, {"keys": [public_jwk]})

        if args.apply:
            exists = subprocess.run(
                ["kubectl", "get", "secret", args.name, "-n", args.namespace],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0
            if exists:
                raise SystemExit(f"Secret {args.namespace}/{args.name} already exists; refusing to replace signing authority")
            manifest = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": args.name, "namespace": args.namespace},
                "immutable": True,
                "type": "Opaque",
                "data": {
                    "signing-key.json": base64.b64encode(private_path.read_bytes()).decode(),
                    "jwks.json": base64.b64encode(public_path.read_bytes()).decode(),
                },
            }
            subprocess.run(
                ["kubectl", "apply", "-f", "-"],
                input=json.dumps(manifest).encode(),
                check=True,
            )
        else:
            print(f"Generated {private_path} and {public_path}; keep the private JWK out of source control.")


if __name__ == "__main__":
    os.umask(0o077)
    main()
