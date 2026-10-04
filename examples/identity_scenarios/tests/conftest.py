"""Test harness: one disposable estate per pytest session (or an existing one named by AXIOM_COOKBOOK_STATE), a fresh
fixture namespace per test, cleanup of each test's own records, and a sanitized evidence file."""
from __future__ import annotations

import datetime as dt
import json
import os
import platform
import subprocess
from pathlib import Path

import pytest

from axiom_cookbook import estate as estate_module
from axiom_cookbook.context import Context
from axiom_cookbook.estate import Estate

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"
_results: list[dict] = []


@pytest.fixture(scope="session")
def estate():
    state = os.environ.get("AXIOM_COOKBOOK_STATE")
    if state:
        yield Estate.load(state)
        return
    extra = {}
    owned = estate_module.up(extra_env=extra)
    try:
        yield owned
    finally:
        leaks = _token_shaped_strings_in_logs(owned)
        notes = estate_module.down(owned)
        CLEANUP.update(estate_down_skipped=notes)
        if notes:
            pytest.fail(f"estate cleanup skipped items for manual review: {notes}")
        if leaks:
            pytest.fail(f"server logs contain {leaks} token-shaped value(s); credentials must never be logged")


def _token_shaped_strings_in_logs(owned) -> int:
    """Credentials must not reach the issuer's logs either (URLs, errors, traces). Counts JWT-shaped strings."""
    import re
    pattern = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")
    total = 0
    for log in (owned.run_dir / "logs").glob("*.log"):
        total += len(pattern.findall(log.read_bytes()))
    LOG_SCAN.update(logs_scanned=[p.name for p in (owned.run_dir / "logs").glob("*.log")], token_shaped_matches=total)
    return total


LOG_SCAN: dict = {}
CLEANUP: dict = {}


@pytest.fixture(scope="session")
def base_context(estate):
    return Context.from_estate(estate, quiet=True)


@pytest.fixture
def ctx(base_context, request):
    child = base_context.child()
    yield child
    report = child.registry.cleanup()
    if report["failed"]:
        pytest.fail(f"cleanup failed for {request.node.name}: {report['failed']}")


def record(outcome) -> None:
    _results.append({"example": outcome.example, "allowed": outcome.allowed, "denied": outcome.denied,
                     "facts": outcome.facts, "consumer_must": outcome.consumer_must})


_COUNTS = {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "errors": 0}
_SKIPS: list[str] = []


def pytest_runtest_logreport(report):
    """Counts each test once by its real outcome (setup/teardown errors count as errors, not passes)."""
    if report.when == "call":
        if hasattr(report, "wasxfail"):
            _COUNTS["xfailed" if report.skipped else "xpassed"] += 1
        elif report.passed:
            _COUNTS["passed"] += 1
        elif report.failed:
            _COUNTS["failed"] += 1
        elif report.skipped:
            _COUNTS["skipped"] += 1
            _SKIPS.append(report.nodeid)
    elif report.failed:
        _COUNTS["errors"] += 1
    elif report.when == "setup" and report.skipped:
        _COUNTS["skipped"] += 1
        _SKIPS.append(report.nodeid)


def pytest_sessionfinish(session, exitstatus):
    EVIDENCE.mkdir(exist_ok=True)
    repo = Path(__file__).resolve().parents[3]
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True).stdout
    from axiom_cookbook import evidence
    payload = {
        "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "exit_status": int(exitstatus), "collected": session.testscollected, "counts": dict(_COUNTS),
        "skipped_tests": list(_SKIPS), "failed": session.testsfailed,
        "command": " ".join(["pytest", *session.config.invocation_params.args]),
        "opt_ins": {k: "set" for k in ("AXIOM_COOKBOOK_ALLOW_DISRUPTIVE", "AXIOM_COOKBOOK_STATE") if os.environ.get(k)},
        "git_head": head, "dirty_entries": len(dirty.splitlines()),
        "dirty_status_hash": __import__("hashlib").sha256(dirty.encode()).hexdigest()[:16],
        "source_fingerprint": evidence.content_fingerprint(),
        "dependencies": evidence.dependency_versions(),
        "python": platform.python_version(), "outcomes": _results, "server_log_scan": LOG_SCAN,
        "cleanup": CLEANUP,
    }
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    # The evidence file must never carry a credential; a JWT-shaped string fails the whole run.
    if __import__("re").search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.", text):
        session.exitstatus = 1
        text = json.dumps({"error": "evidence withheld: it contained a token-shaped value"})
    (EVIDENCE / "last-run.json").write_text(text)
