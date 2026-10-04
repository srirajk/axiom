"""Offline: cleanup (``down``/``reap``) signals or deletes only what provably belongs to one exact cookbook run.

Signals, directory deletion, Docker and ``ps`` are all mocked; no real process is signalled and nothing outside
pytest's temporary directory is touched.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from axiom_cookbook import estate as E
from axiom_cookbook.redaction import Secret

STARTED = "Sat Oct  3 16:00:00 2026"


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A private temp dir and recorders in place of every side effect."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    calls = {"signals": [], "removed": [], "docker_rm": [], "ps": {}}
    monkeypatch.setattr(E, "_signal_group", lambda pid, sig: calls["signals"].append((pid, sig)))
    monkeypatch.setattr(E, "_remove_tree", lambda path: calls["removed"].append(Path(path).name))
    monkeypatch.setattr(E, "_process_info", lambda pid: calls["ps"].get(pid))
    containers = {}  # id -> run label

    def docker(*args, check=True):
        if args[0] == "ps":
            wanted = args[-1].split("=", 2)
            return "\n".join(c for c, run in containers.items() if len(wanted) < 3 or run == wanted[2])
        if args[0] == "inspect":
            return containers.get(args[-1], "")
        if args[0] == "rm":
            calls["docker_rm"].append(args[-1])
        return ""

    monkeypatch.setattr(E, "_docker", docker)
    monkeypatch.setattr(E, "_PROCESSES", {})
    calls["containers"] = containers
    calls["tmp"] = tmp_path
    return calls


def owned_run(tmp: Path, run_id: str = "0a1b2c3d", pid: int | None = 4242, tag: str = "f" * 32) -> E.Estate:
    run_dir = tmp / f"{E.RUN_DIR_PREFIX}{run_id}-abc_123"
    run_dir.mkdir(mode=0o700)
    os.chmod(run_dir, 0o700)
    (run_dir / E.OWNER_FILE).write_text(json.dumps({"run_id": run_id, "owner_tag": tag, "uid": os.getuid()}))
    estate = E.Estate(run_id, run_dir, "http://127.0.0.1:1", "ckbk-" + run_id, "ckbk-root",
                      Secret("x" * 20, "pw"), server_pid=pid, owner_tag=tag, server_started=STARTED)
    estate.save()
    return estate


def our_process(estate: E.Estate) -> dict:
    return {"uid": os.getuid(), "pgid": estate.server_pid, "started": STARTED,
            "command": f"/jdk/bin/java -D{E.OWNER_PROPERTY}={estate.run_id}.{estate.owner_tag} -jar iam.jar"}


# ------------------------------------------------------------------------------------------------ stale / forged PID
def test_stale_pid_is_not_signalled_and_the_owned_dead_run_is_reaped(world):
    run = owned_run(world["tmp"])                       # pid 4242 is not running: ps knows nothing about it
    world["containers"]["c-own"] = run.run_id
    report = E.reap()
    assert world["signals"] == []
    assert world["removed"] == [run.run_dir.name] and world["docker_rm"] == ["c-own"]
    assert report["skipped"] == []


@pytest.mark.parametrize("impostor", [
    {"command": "/sbin/launchd"},                                   # PID reused by an unrelated process
    {"started": "Sat Oct  3 09:00:00 2026"},                        # same tag text but a different process start
    {"uid": os.getuid() + 1},                                       # another user's process
    {"pgid": 1},                                                    # not the leader of its own process group
    {"command": f"java -D{E.OWNER_PROPERTY}=0a1b2c3d.{'0' * 32} -jar iam.jar"},  # another run's tag
])
def test_forged_or_reused_pid_is_never_signalled(world, impostor):
    run = owned_run(world["tmp"])
    world["ps"][run.server_pid] = {**our_process(run), **impostor}
    report = E.reap()
    assert world["signals"] == [] and world["removed"] == [] and world["docker_rm"] == []
    assert len(report["skipped"]) == 1 and "review manually" in report["skipped"][0]
    notes = E.down(E.Estate.load(run.state_file))
    assert world["signals"] == [] and world["removed"] == []
    assert any("not signalled" in n for n in notes) and any("kept" in n for n in notes)


def test_a_running_pid_without_ownership_evidence_is_never_signalled(world):
    run = owned_run(world["tmp"])
    state = json.loads(run.state_file.read_text())
    state.update(owner_tag=None, server_started=None)               # e.g. a state file written before ownership tags
    run.state_file.write_text(json.dumps(state))
    world["ps"][run.server_pid] = our_process(run)
    notes = E.down(E.Estate.load(run.state_file))
    assert world["signals"] == [] and world["removed"] == [] and notes


# ------------------------------------------------------------------------------------ unrelated same-prefix dirs
def test_unrelated_same_prefix_directories_are_not_deleted(world, tmp_path_factory):
    tmp = world["tmp"]
    no_marker = tmp / f"{E.RUN_DIR_PREFIX}11111111-noowner"
    no_marker.mkdir(mode=0o700)
    (no_marker / "estate.json").write_text("{}")
    os.chmod(no_marker / "estate.json", 0o600)
    other_tag = owned_run(tmp, run_id="22222222")
    marker = json.loads((other_tag.run_dir / E.OWNER_FILE).read_text())
    (other_tag.run_dir / E.OWNER_FILE).write_text(json.dumps({**marker, "owner_tag": "e" * 32}))
    wide_open = owned_run(tmp, run_id="33333333")
    os.chmod(wide_open.run_dir, 0o755)
    outside = tmp_path_factory.mktemp("precious")
    (outside / "keep.txt").write_text("not the cookbook's")
    (tmp / f"{E.RUN_DIR_PREFIX}44444444-link").symlink_to(outside)
    (tmp / f"{E.RUN_DIR_PREFIX}notes").mkdir()
    world["containers"]["c-foreign"] = "99999999"                    # labelled, but no verified run owns it

    report = E.reap()
    assert world["removed"] == [] and world["signals"] == [] and world["docker_rm"] == []
    assert len(report["skipped"]) == 6 and (outside / "keep.txt").exists()

    forged = E.Estate.load(wide_open.state_file)
    forged.run_dir = outside                                         # a state file pointing somewhere else
    E.down(forged)
    assert world["removed"] == []


# ----------------------------------------------------------------------------------------------- valid owned run
def test_a_valid_live_run_is_left_to_down_and_down_stops_and_removes_it(world):
    run = owned_run(world["tmp"])
    world["ps"][run.server_pid] = our_process(run)
    world["containers"]["c-own"] = run.run_id
    report = E.reap()
    assert world["signals"] == [] and world["removed"] == []
    assert "still active" in report["skipped"][0]

    original = E._signal_group

    def signal_and_exit(pid, sig):
        original(pid, sig)
        world["ps"].pop(pid, None)                                    # the owned process exits after SIGTERM

    E._signal_group = signal_and_exit
    try:
        loaded = E.Estate.load(run.state_file)
        loaded.containers = {"postgres": "c-own"}
        notes = E.down(loaded)
    finally:
        E._signal_group = original
    assert world["signals"] == [(run.server_pid, 15)]
    assert world["removed"] == [run.run_dir.name] and world["docker_rm"] == ["c-own"] and notes == []
