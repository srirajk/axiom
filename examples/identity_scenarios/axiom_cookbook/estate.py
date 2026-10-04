"""A disposable, isolated Axiom estate: PostgreSQL 16, Redis 7, Cerbos and a real Axiom process.

This mirrors the supported first-start sequence (``compose.yaml``): a one-shot bootstrap process creates the first
tenant and its root administrator, then the long-running server starts. Everything is owned by one run:

* containers carry the label ``axiom.cookbook.run=<run id>`` and publish only on 127.0.0.1;
* the run directory (mode 0700) holds the runtime-policy mount, the Cerbos audit log and the server logs;
* generated credentials (database password, master key, root administrator password) live in memory and in the
  0600 state file only — never on a command line, in stdout or in an environment of an unrelated process.

``python -m axiom_cookbook.estate up`` starts one and prints the path of its state file; ``down`` stops it;
``reap`` removes containers and run directories left behind by interrupted runs. Nothing here touches shared Docker
volumes, other containers or any non-loopback endpoint.

Cleanup acts only on what it can prove belongs to one exact cookbook run (see ``process_status`` and ``dir_owned``):

* a run directory is deleted only if it is a real directory directly in the temp dir, named for its run id, owned by
  this user with mode 0700, and holds an ownership marker whose run id and random owner tag match its 0600 state file;
* the server is signalled only if this Python process still holds its child handle, or ``ps`` shows a process of this
  user that leads its own process group, started at the recorded time and carries this run's owner tag on its
  command line (``-Daxiom.cookbook.owner=<run>.<tag>``). A PID that merely appears in a state file proves nothing;
* containers are removed only if their cookbook label carries this run's id.

Anything that cannot be proven is skipped and reported for manual review, never signalled or deleted.
"""
from __future__ import annotations

import argparse
import re
import base64
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from .redaction import Secret

REPO = Path(__file__).resolve().parents[3]
JAR = REPO / "server" / "target" / "iam-service-1.0.0.jar"
LABEL = "axiom.cookbook.run"
RUN_DIR_PREFIX = "axiom-cookbook-"
OWNER_FILE = ".cookbook-owner"
OWNER_PROPERTY = "axiom.cookbook.owner"
_RUN_DIR_NAME = re.compile(r"^axiom-cookbook-([0-9a-f]{8})-[a-z0-9_]+$")
POSTGRES_IMAGE = "postgres:16"
REDIS_IMAGE = "redis:7-alpine"
CERBOS_IMAGE = "ghcr.io/cerbos/cerbos:0.53.0"
# Generic, consumer-neutral business scopes the cookbook's examples use.
APPROVED_SCOPES = "orders.read,orders.write,ledger.read,ledger.write,reports.read,payments.execute,payments.admin"


@dataclass
class Estate:
    run_id: str
    run_dir: Path
    base_url: str
    tenant_id: str
    root_admin_username: str
    root_admin_password: Secret
    containers: dict[str, str] = field(default_factory=dict)
    server_pid: int | None = None
    java_home: str | None = None
    extra_env: dict[str, str] = field(default_factory=dict)
    owner_tag: str | None = None          # random, per run; ties marker, state and server command line together
    server_started: str | None = None     # the server process's start time as reported by ps (anti PID reuse)

    @property
    def state_file(self) -> Path:
        return self.run_dir / "estate.json"

    # ------------------------------------------------------------------------------------------------------------
    def save(self) -> None:
        data = {
            "run_id": self.run_id, "run_dir": str(self.run_dir), "base_url": self.base_url,
            "tenant_id": self.tenant_id, "root_admin_username": self.root_admin_username,
            "root_admin_password": self.root_admin_password.reveal(), "containers": self.containers,
            "server_pid": self.server_pid, "owner_tag": self.owner_tag, "server_started": self.server_started,
        }
        self.state_file.write_text(json.dumps(data))
        os.chmod(self.state_file, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def load(cls, path: str | Path) -> "Estate":
        p = Path(path)
        mode = p.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(f"{p} must not be readable by group/other")
        d = json.loads(p.read_text())
        return cls(d["run_id"], Path(d["run_dir"]), d["base_url"], d["tenant_id"], d["root_admin_username"],
                   Secret(d["root_admin_password"], "root administrator password"), d["containers"],
                   d.get("server_pid"), owner_tag=d.get("owner_tag"), server_started=d.get("server_started"))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker(*args: str, check: bool = True) -> str:
    out = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f"docker {args[0]} failed: {out.stderr.strip()[:500]}")
    return out.stdout.strip()


def _published(container: str, port: int) -> int:
    mapping = _docker("port", container, f"{port}/tcp")
    return int(mapping.splitlines()[0].rsplit(":", 1)[1])


def _wait(what: str, check, timeout: float = 120.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if check():
                return
        except Exception:
            pass
        time.sleep(1.0)
    raise TimeoutError(f"{what} did not become ready in {timeout:.0f}s")


def _java() -> str:
    home = os.environ.get("AXIOM_COOKBOOK_JAVA_HOME") or os.environ.get("JAVA_HOME") \
        or "/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home"
    java = Path(home) / "bin" / "java"
    if not java.exists():
        raise RuntimeError("Java 25 is required: set AXIOM_COOKBOOK_JAVA_HOME")
    return str(java)


def up(extra_env: dict[str, str] | None = None, jar: Path = JAR) -> Estate:
    """Starts a fresh estate. ``extra_env`` lets a test-owned run add server settings (never secrets)."""
    if not jar.exists():
        raise RuntimeError(f"{jar} not found: build it with `mvn -o -B package -DskipTests` in server/")
    run_id = secrets.token_hex(4)
    run_dir = Path(tempfile.mkdtemp(prefix=RUN_DIR_PREFIX + run_id + "-"))
    os.chmod(run_dir, stat.S_IRWXU)
    for sub in ("runtime-policies", "cerbos-audit", "logs"):
        (run_dir / sub).mkdir()
    # Cerbos runs as a non-root user inside its container; its two writable mounts must accept it.
    os.chmod(run_dir / "runtime-policies", 0o777)
    os.chmod(run_dir / "cerbos-audit", 0o777)
    db_password = secrets.token_urlsafe(18)
    master_key = base64.b64encode(secrets.token_bytes(32)).decode()
    root_password = Secret(secrets.token_urlsafe(24) + "Aa1!", "root administrator password")
    tenant = "ckbk-" + run_id
    estate = Estate(run_id, run_dir, "", tenant, "ckbk-root", root_password, owner_tag=secrets.token_hex(16))
    marker = run_dir / OWNER_FILE
    marker.write_text(json.dumps({"run_id": run_id, "owner_tag": estate.owner_tag, "uid": os.getuid()}))
    os.chmod(marker, stat.S_IRUSR | stat.S_IWUSR)
    estate.save()  # from here on an interrupted run is recognisable (and reapable) as this run
    labels = ["--label", f"{LABEL}={run_id}"]
    try:
        estate.containers["postgres"] = _docker(
            "run", "-d", "--rm", *labels, "-e", "POSTGRES_USER=axiom", "-e", "POSTGRES_DB=axiom",
            "--env-file", _env_file(run_dir, {"POSTGRES_PASSWORD": db_password}),
            "-p", "127.0.0.1::5432", POSTGRES_IMAGE)
        estate.containers["redis"] = _docker("run", "-d", "--rm", *labels, "-p", "127.0.0.1::6379", REDIS_IMAGE)
        estate.containers["cerbos"] = _docker(
            "run", "-d", "--rm", *labels, "-p", "127.0.0.1::3592", "-p", "127.0.0.1::3593",
            "-v", f"{REPO / 'platform-policy' / 'config.yaml'}:/conf/config.yaml:ro",
            "-v", f"{REPO / 'platform-policy' / 'policies'}:/policies/base:ro",
            "-v", f"{run_dir / 'runtime-policies'}:/policies/runtime",
            "-v", f"{run_dir / 'cerbos-audit'}:/var/log/cerbos",
            CERBOS_IMAGE, "server", "--config=/conf/config.yaml")
        pg = _published(estate.containers["postgres"], 5432)
        rd = _published(estate.containers["redis"], 6379)
        cerbos_http = _published(estate.containers["cerbos"], 3592)
        cerbos_grpc = _published(estate.containers["cerbos"], 3593)
        _wait("postgres", lambda: subprocess.run(["docker", "exec", estate.containers["postgres"], "pg_isready",
                                                  "-U", "axiom", "-d", "axiom"], capture_output=True).returncode == 0)
        _wait("redis", lambda: _docker("exec", estate.containers["redis"], "redis-cli", "ping") == "PONG")
        _wait("cerbos", lambda: requests.get(f"http://127.0.0.1:{cerbos_http}/_cerbos/health", timeout=2).ok)
        estate.save()

        port = _free_port()
        estate.base_url = f"http://127.0.0.1:{port}"
        env = {
            "SPRING_DATASOURCE_URL": f"jdbc:postgresql://127.0.0.1:{pg}/axiom",
            "SPRING_DATASOURCE_USERNAME": "axiom", "SPRING_DATASOURCE_PASSWORD": db_password,
            "SPRING_DATA_REDIS_HOST": "127.0.0.1", "SPRING_DATA_REDIS_PORT": str(rd),
            "AXIOM_SECRETS_MASTER_KEY": master_key, "IAM_ISSUER_URL": estate.base_url,
            "IAM_SIGNING_KEY_PATH": str(run_dir / "signing-key.json"),
            "CERBOS_HOST": "127.0.0.1", "CERBOS_PORT": str(cerbos_grpc), "CERBOS_HTTP_PORT": str(cerbos_http),
            "IAM_POLICY_STUDIO_BASE_BUNDLE_DIR": str(REPO / "platform-policy" / "policies"),
            "IAM_POLICY_STUDIO_RUNTIME_POLICIES_DIR": str(run_dir / "runtime-policies"),
            "IAM_POLICY_STUDIO_PLATFORM_CONTRACT_PATH": str(REPO / "platform-contract" / "axiom-platform-contract.json"),
            "IAM_TENANCY_POLICY_STAGING_DIR": str(run_dir / "policy-staging"),
            "IAM_OAUTH2_APPROVED_BUSINESS_SCOPES": APPROVED_SCOPES,
            # The operator logs in through the browser authorization-code flow; the redirect is never contacted.
            "IAM_AXIOM_ADMIN_REDIRECT_URI": "http://127.0.0.1:9/cookbook/callback",
            "IAM_AXIOM_ADMIN_POST_LOGOUT_REDIRECT_URI": "http://127.0.0.1:9/cookbook/logged-out",
            # Axiom ships no customer-code delivery provider. In this disposable loopback estate only, the built-in
            # local-demo aid returns the e-mail verification code to the *customer's own* registration or
            # verification-challenge call (never to an administrator) so the real /verifications endpoint can run.
            # Axiom refuses to start with it on a non-loopback issuer or beside a real provider; recovery codes are
            # never disclosed. Evidence labels every such verification "LOCAL_DEMO (simulated delivery)".
            "IAM_CIAM_LOCAL_DEMO_CHALLENGE_DISCLOSURE": "true",
            # Cookbook profile: only the supported browser login path for people (story 0.6 switch).
            "IAM_AUTH_LEGACY_PASSWORD_LOGIN_ENABLED": "false", "IAM_AUTH_IMPERSONATION_ENABLED": "false",
            # Short lifetimes so expiry and rotation overlap are observable within a test run.
            "IAM_OAUTH2_CLIENT_CREDENTIALS_TTL": "PT30S", "IAM_CLIENT_SECRET_ROTATION_OVERLAP": "PT15S",
            "SERVER_PORT": str(port), "JAVA_TOOL_OPTIONS": "-Xmx512m",
        }
        env.update(extra_env or {})
        estate.extra_env = dict(extra_env or {})
        _bootstrap(estate, env, jar)
        estate.server_pid = _start_server(estate, env, jar)
        _wait("axiom", lambda: requests.get(estate.base_url + "/actuator/health", timeout=2).json().get("status") == "UP",
              timeout=180)
        estate.save()
        _remember_env(estate, env)
        return estate
    except BaseException:
        down(estate)
        raise


def _env_file(run_dir: Path, values: dict[str, str]) -> str:
    path = run_dir / ("env-" + secrets.token_hex(4))
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return str(path)


def _bootstrap(estate: Estate, env: dict[str, str], jar: Path) -> None:
    boot = dict(os.environ)
    boot.update(env)
    boot.update({
        "AXIOM_BOOTSTRAP_ENABLED": "true", "AXIOM_BOOTSTRAP_TENANT_ID": estate.tenant_id,
        "AXIOM_BOOTSTRAP_TENANT_NAME": "Cookbook " + estate.run_id, "AXIOM_BOOTSTRAP_TENANT_SLUG": estate.tenant_id,
        "AXIOM_BOOTSTRAP_ADMIN_ID": estate.root_admin_username, "AXIOM_BOOTSTRAP_ADMIN_USERNAME": estate.root_admin_username,
        "AXIOM_BOOTSTRAP_ADMIN_EMAIL": f"{estate.root_admin_username}@cookbook.invalid",
        "AXIOM_BOOTSTRAP_ADMIN_PASSWORD": estate.root_admin_password.reveal(),
        "IAM_SIGNING_KEY_ALLOW_GENERATION": "true",
    })
    with open(estate.run_dir / "logs" / "bootstrap.log", "wb") as log:
        result = subprocess.run([_java(), "-jar", str(jar), "--spring.main.web-application-type=none"],
                                env=boot, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"bootstrap failed (exit {result.returncode}); see {estate.run_dir / 'logs' / 'bootstrap.log'}")


_PROCESSES: dict[int, subprocess.Popen] = {}


def _start_server(estate: Estate, env: dict[str, str], jar: Path) -> int:
    run = dict(os.environ)
    run.update(env)
    run["IAM_SIGNING_KEY_ALLOW_GENERATION"] = "false"
    log = open(estate.run_dir / "logs" / "server.log", "ab")
    process = subprocess.Popen([_java(), f"-D{OWNER_PROPERTY}={estate.run_id}.{estate.owner_tag}", "-jar", str(jar)],
                               env=run, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    _PROCESSES[process.pid] = process
    info = _process_info(process.pid)
    estate.server_started = info["started"] if info else None
    estate.server_pid = process.pid
    estate.save()
    return process.pid


def _remember_env(estate: Estate, env: dict[str, str]) -> None:
    """Keeps the server environment (0600) so a test-owned restart can reuse it."""
    path = estate.run_dir / "server.env.json"
    path.write_text(json.dumps(env))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def restart_server(estate: Estate, jar: Path = JAR) -> None:
    """Test-owned restart of the Axiom process only (state stays in PostgreSQL/Redis)."""
    note = _stop_server(estate)
    if note:
        raise RuntimeError(f"restart refused: {note}")
    env = json.loads((estate.run_dir / "server.env.json").read_text())
    estate.server_pid = _start_server(estate, env, jar)
    _wait("axiom", lambda: requests.get(estate.base_url + "/actuator/health", timeout=2).json().get("status") == "UP",
          timeout=180)
    estate.save()


def pause(estate: Estate, service: str) -> None:
    _docker("pause", estate.containers[service])


def unpause(estate: Estate, service: str) -> None:
    _docker("unpause", estate.containers[service])


# ---------------------------------------------------------------------------------------------- ownership checks
def _process_info(pid: int) -> dict | None:
    """uid, process group, start time and command line of a live process, or None."""
    out = subprocess.run(["ps", "-o", "uid=,pgid=,lstart=,command=", "-p", str(int(pid))],
                         capture_output=True, text=True)
    parts = out.stdout.split(None, 7) if out.returncode == 0 else []
    if len(parts) < 8:
        return None
    return {"uid": int(parts[0]), "pgid": int(parts[1]), "started": " ".join(parts[2:7]), "command": parts[7].strip()}


def _signal_group(pid: int, sig: int) -> None:
    os.killpg(pid, sig)


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path)


def process_status(estate: Estate) -> tuple[str, str]:
    """``("owned", why)`` if the recorded server is provably this run's live process; ``("gone", why)`` if nothing
    needs signalling; ``("unproven", why)`` if some process holds the PID but is not proven to be ours."""
    pid = estate.server_pid
    if not pid:
        return "gone", "no server pid recorded"
    handle = _PROCESSES.get(pid)
    if handle is not None:
        return ("owned", "child handle held by this process") if handle.poll() is None else ("gone", "child exited")
    info = _process_info(pid)
    if info is None:
        return "gone", f"pid {pid} is not running"
    if not estate.owner_tag or not estate.server_started:
        return "unproven", f"pid {pid} is running but the state has no owner tag/start time"
    tag = f"-D{OWNER_PROPERTY}={estate.run_id}.{estate.owner_tag}"
    failed = [name for name, ok in (("uid", info["uid"] == os.getuid()), ("process group", info["pgid"] == pid),
                                    ("start time", info["started"] == estate.server_started),
                                    ("owner tag", tag in info["command"].split())) if not ok]
    if failed:
        return "unproven", f"pid {pid} is running but does not match this run ({', '.join(failed)})"
    return "owned", "uid, process group, start time and owner tag match"


def dir_owned(path: Path, run_id: str | None, owner_tag: str | None) -> tuple[bool, str]:
    """True only for this exact run's directory (see module docstring)."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_dir():
            return False, "not a real directory"
        if path.parent.resolve() != Path(tempfile.gettempdir()).resolve():
            return False, "not directly in the temp directory"
        match = _RUN_DIR_NAME.match(path.name)
        if not match or (run_id is not None and match.group(1) != run_id):
            return False, "name does not carry this run id"
        st = path.lstat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            return False, "not owned by this user with mode 0700"
        marker = path / OWNER_FILE
        if marker.is_symlink() or not marker.is_file() or marker.lstat().st_uid != os.getuid():
            return False, "no ownership marker"
        data = json.loads(marker.read_text())
        if data.get("run_id") != match.group(1) or not owner_tag or data.get("owner_tag") != owner_tag:
            return False, "ownership marker does not match the run's state"
        return True, "owned"
    except (OSError, ValueError) as unreadable:
        return False, f"unreadable ({type(unreadable).__name__})"


# ------------------------------------------------------------------------------------------------------- cleanup
def _stop_server(estate: Estate) -> str | None:
    """Stops the server only if it is provably this run's. Returns a manual-review note otherwise."""
    status, why = process_status(estate)
    if status == "gone":
        _PROCESSES.pop(estate.server_pid or -1, None)
        estate.server_pid = None
        return None
    if status == "unproven":
        return f"server not signalled: {why}; review manually"
    pid = estate.server_pid
    handle = _PROCESSES.pop(pid, None)
    _signal_group(pid, 15)
    if handle is not None:
        try:
            handle.wait(timeout=30)
        except subprocess.TimeoutExpired:
            _signal_group(pid, 9)
            handle.wait(timeout=10)
    else:
        for _ in range(60):
            if process_status(estate)[0] != "owned":
                break
            time.sleep(0.5)
        else:
            _signal_group(pid, 9)
    estate.server_pid = None
    return None


def _remove_run_containers(run_id: str) -> list[str]:
    removed = []
    for container in _docker("ps", "-aq", "--filter", f"label={LABEL}={run_id}", check=False).split():
        label = _docker("inspect", "-f", "{{index .Config.Labels \"" + LABEL + "\"}}", container, check=False)
        if label == run_id:
            _docker("rm", "-f", container, check=False)
            removed.append("container " + container)
    return removed


def down(estate: Estate) -> list[str]:
    """Stops this run's server and containers and deletes its run directory — each only if provably this run's.
    Returns notes for anything skipped (manual review)."""
    notes = []
    stopped = _stop_server(estate)
    if stopped:
        notes.append(stopped)
    for container in estate.containers.values():
        label = _docker("inspect", "-f", "{{index .Config.Labels \"" + LABEL + "\"}}", container, check=False)
        if label == estate.run_id:
            _docker("rm", "-f", container, check=False)
    if os.environ.get("AXIOM_COOKBOOK_KEEP_RUN_DIR") == "1":
        return notes
    if stopped:
        notes.append(f"run dir {estate.run_dir.name} kept: its server could not be proven stopped")
        return notes
    owned, why = dir_owned(estate.run_dir, estate.run_id, estate.owner_tag)
    if owned:
        _remove_tree(estate.run_dir)
    else:
        notes.append(f"run dir {estate.run_dir.name} not deleted: {why}; review manually")
    return notes


def reap() -> dict[str, list[str]]:
    """Removes leftovers of *interrupted* runs that are provably cookbook runs. Live runs, unproven processes,
    unverifiable directories and containers without a verified run are reported, not touched."""
    removed, skipped, reaped_runs = [], [], set()
    tmp = Path(tempfile.gettempdir())
    for d in sorted(tmp.glob(RUN_DIR_PREFIX + "*")):
        match = _RUN_DIR_NAME.match(d.name)
        try:
            state = Estate.load(d / "estate.json") if match and not d.is_symlink() else None
        except (OSError, ValueError, KeyError, PermissionError):
            state = None
        owned, why = dir_owned(d, match.group(1) if match else None, state.owner_tag if state else None)
        if state is None or not owned or state.run_id != match.group(1) \
                or state.run_dir.resolve() != d.resolve():
            skipped.append(f"{d.name}: {why if not owned else 'state does not describe this directory'}")
            continue
        status, why = process_status(state)
        if status == "owned":
            skipped.append(f"{d.name}: run is still active ({why}); stop it with `down --state`")
            continue
        if status == "unproven":
            skipped.append(f"{d.name}: {why}; not signalled or deleted, review manually")
            continue
        removed += _remove_run_containers(state.run_id)
        _remove_tree(d)
        reaped_runs.add(state.run_id)
        removed.append("run dir " + d.name)
    for container in _docker("ps", "-aq", "--filter", f"label={LABEL}", check=False).split():
        run = _docker("inspect", "-f", "{{index .Config.Labels \"" + LABEL + "\"}}", container, check=False)
        if run not in reaped_runs:
            skipped.append(f"container {container} (run {run}): no verified interrupted run owns it; review manually")
    return {"removed": removed, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["up", "down", "reap"])
    parser.add_argument("--state", help="state file printed by `up` (for `down`)")
    args = parser.parse_args(argv)
    if args.command == "up":
        estate = up()
        print(f"Axiom estate {estate.run_id} is up at {estate.base_url} (tenant {estate.tenant_id}).")
        print(f"State file (0600, contains generated credentials): {estate.state_file}")
        print(f"export AXIOM_COOKBOOK_STATE={estate.state_file}")
    elif args.command == "down":
        if not args.state:
            parser.error("--state is required for down")
        notes = down(Estate.load(args.state))
        print("Estate stopped and removed." if not notes else "Estate stopped; skipped for manual review:")
        for note in notes:
            print("  " + note)
    else:
        report = reap()
        for item in report["removed"]:
            print("removed", item)
        for item in report["skipped"]:
            print("skipped", item)
    return 0


if __name__ == "__main__":
    sys.exit(main())
