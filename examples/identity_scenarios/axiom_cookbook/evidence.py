"""Reproducible run evidence: a deterministic fingerprint of the source that was actually exercised, and the versions
of everything the run depended on.

The fingerprint hashes file *content* (not ``git status``), so it changes when any relevant file changes — tracked or
untracked — and stays identical for identical trees. It covers the cookbook, the server source and build file the
jar is built from, and the policy/contract files the estate mounts. It never reads virtualenvs, caches, logs, run
evidence, failure artifacts, or files that look like secrets (keys, certificates, ``.env``, state files).
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import os
import platform
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
COOKBOOK = REPO / "examples" / "identity_scenarios"

# (root, relative to REPO) — what a cookbook run depends on.
SOURCE_ROOTS = ("examples/identity_scenarios", "server/src/main", "server/pom.xml",
                "platform-policy", "platform-contract")
EXCLUDED_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", "evidence", "artifacts", "logs", "target",
                 "node_modules", ".git", ".idea"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".log", ".pem", ".key", ".p12", ".jks", ".pfx", ".crt", ".der")
EXCLUDED_NAMES = {".env", "estate.json", "signing-key.json", "server.env.json", ".cookbook-owner", ".DS_Store"}


def _excluded(relative: Path) -> bool:
    parts = relative.parts
    if any(p in EXCLUDED_DIRS or p.endswith(".egg-info") for p in parts[:-1]):
        return True
    name = parts[-1]
    return (name in EXCLUDED_NAMES or name.startswith(".env") or name.startswith("env-")
            or name.endswith(EXCLUDED_SUFFIXES))


def source_files(repo: Path = REPO, roots: tuple[str, ...] = SOURCE_ROOTS) -> list[Path]:
    """Every relevant file, sorted by repository-relative path. Symlinks are not followed."""
    found: list[Path] = []
    for root in roots:
        base = repo / root
        if base.is_file() and not base.is_symlink():
            found.append(base)
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            rel_dir = Path(dirpath).relative_to(repo)
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS and not d.endswith(".egg-info"))
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if not path.is_symlink() and path.is_file() and not _excluded(rel_dir / name):
                    found.append(path)
    return sorted(found, key=lambda p: p.relative_to(repo).as_posix())


def content_fingerprint(repo: Path = REPO, roots: tuple[str, ...] = SOURCE_ROOTS) -> dict:
    """SHA-256 over (relative path, length, content) of every relevant file, in sorted order."""
    digest = hashlib.sha256()
    files = source_files(repo, roots)
    for path in files:
        rel = path.relative_to(repo).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(rel).to_bytes(4, "big") + rel + len(data).to_bytes(8, "big") + data)
    return {"sha256": digest.hexdigest(), "files": len(files), "roots": list(roots)}


def _version(dist: str) -> str | None:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return None


def _command(*args: str) -> str | None:
    try:
        out = subprocess.run(list(args), capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or out.stderr).strip()
    return text.splitlines()[0] if out.returncode == 0 and text else None


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def dependency_versions() -> dict:
    from . import estate  # local import: estate imports requests, which this module does not need
    try:
        java = _command(estate._java(), "-version")  # java prints its version on stderr
    except RuntimeError:
        java = None
    images = {}
    for image in (estate.POSTGRES_IMAGE, estate.REDIS_IMAGE, estate.CERBOS_IMAGE):
        images[image] = _command("docker", "image", "inspect", "-f", "{{.Id}}", image)
    return {
        "python": platform.python_version(),
        "packages": {d: _version(d) for d in ("requests", "PyJWT", "cryptography", "pytest", "playwright")},
        "java": java,
        "docker": _command("docker", "version", "-f", "{{.Server.Version}}"),
        "images": images,
        "server_jar_sha256": _sha256(estate.JAR),
    }
