"""Offline: the evidence fingerprint is a deterministic hash of relevant source *content*, independent of git."""
from __future__ import annotations

from axiom_cookbook.evidence import content_fingerprint, source_files

ROOTS = ("examples/identity_scenarios", "server/src/main")


def _tree(repo):
    (repo / "examples/identity_scenarios/oauth").mkdir(parents=True)
    (repo / "server/src/main/java").mkdir(parents=True)
    (repo / "examples/identity_scenarios/oauth/o02.py").write_text("print('flow')\n")
    (repo / "examples/identity_scenarios/untracked_new.py").write_text("x = 1\n")   # untracked files count too
    (repo / "server/src/main/java/A.java").write_text("class A {}\n")


def test_fingerprint_is_deterministic_and_changes_with_source_content(tmp_path):
    _tree(tmp_path)
    first = content_fingerprint(tmp_path, ROOTS)
    assert first == content_fingerprint(tmp_path, ROOTS) and first["files"] == 3

    (tmp_path / "server/src/main/java/A.java").write_text("class A { int x; }\n")
    changed = content_fingerprint(tmp_path, ROOTS)
    assert changed["sha256"] != first["sha256"]

    (tmp_path / "server/src/main/java/A.java").write_text("class A {}\n")
    assert content_fingerprint(tmp_path, ROOTS)["sha256"] == first["sha256"]   # restored content, same hash

    (tmp_path / "examples/identity_scenarios/oauth/o02.py").rename(tmp_path / "examples/identity_scenarios/oauth/o02b.py")
    assert content_fingerprint(tmp_path, ROOTS)["sha256"] != first["sha256"]   # a rename is a change


def test_excluded_material_never_affects_or_enters_the_fingerprint(tmp_path):
    _tree(tmp_path)
    base = content_fingerprint(tmp_path, ROOTS)
    cookbook = tmp_path / "examples/identity_scenarios"
    for rel in (".venv/lib/site.py", "evidence/last-run.json", "artifacts/failure.png", "logs/server.log",
                "__pycache__/m.pyc", "x.egg-info/PKG-INFO", ".env", "env-1234", "estate.json",
                "signing-key.json", "client.pem", "tls.key", "run.log"):
        path = cookbook / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("secret-or-volatile")
    assert content_fingerprint(tmp_path, ROOTS) == base
    assert all("secret" not in p.read_text() for p in source_files(tmp_path, ROOTS))
