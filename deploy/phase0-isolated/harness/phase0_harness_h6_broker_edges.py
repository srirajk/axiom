#!/opt/homebrew/bin/python3.13
"""Phase 0.2 H-6: Axiom broker -> Agent and broker -> resource exchange edges, on a disposable local stack.

Reuses the reviewed H-2 harness ``phase0_harness_h2.py`` unchanged (loaded by its fixed path and SHA-256, which in
turn loads H-1 by digest): its identity fixture, setup, PKCE browser flow, exchange case runner, evaluators, redaction
and API cleanup. H-6 only

  * replaces H-1/H-2's kubectl transport (context/namespace/release/pod/Secret checks and ``kubectl port-forward``)
    with a disposable local stack built from the CURRENT clone: PostgreSQL 16, Redis 7 and a serving Cerbos in
    labelled Docker containers on 127.0.0.1-only random ports, plus the server jar built from ``server/`` run as a
    bootstrap job and then as the server on a 127.0.0.1 port in the harness range;
  * appends denial cases on the two named broker edges (wrong token use, wrong redeeming client, scope,
    destination) to the H-2 expectation table, each placed before the positive case that uses the same subject.

Argus is not involved: the "Gateway" is H-2's broker client registered in Axiom. Nothing is deployed and no
Kubernetes resource is read or changed (kubectl/helm invocations are refused).

ROUTE CLAIM: routes R1-R4 are H-2 fixture topology. A pass proves Axiom's edge semantics for those fixture routes; it
does not claim that Phase 1 provisions R2 (BFF -> Agent), R3 (Agent -> Gateway) or R4 (Agent -> resource).

Secrets (database password, master key, bootstrap admin password) are generated per run into a 0700 work directory
and delivered to the server only as Spring ``configtree`` files and to PostgreSQL only as ``POSTGRES_PASSWORD_FILE``;
none is placed in argv or the environment. The work directory, containers and server are removed at the end.

Usage:
    /opt/homebrew/bin/python3.13 -I -B phase0_harness_h6_broker_edges.py --package h6            # plan only
    /opt/homebrew/bin/python3.13 -I -B phase0_harness_h6_broker_edges.py --package h6 --execute  # run locally

Exit code: as H-2 (0 all cases passed and teardown complete; 1 a case failed; 2 abort, redaction violation,
incomplete cleanup or anything left running).
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

_H2_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase0_harness_h2.py")
# SHA-256 of the reviewed and executed H-2 harness. H-6 refuses to load any other version of it.
H2_SHA256 = "30b949d2aad7ad6400d905666c8fbd68faae67ff824afbbc359936bc3c855f7d"


def _load_h2() -> Any:
    existing = sys.modules.get("phase0_harness_h2")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(_H2_PATH):
            raise ImportError("phase0_harness_h2 already imported from an unexpected location")
        return existing
    with open(_H2_PATH, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != H2_SHA256:
            raise ImportError("phase0_harness_h2.py does not match the reviewed H-2 digest")
    spec = importlib.util.spec_from_file_location("phase0_harness_h2", _H2_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load phase0_harness_h2.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase0_harness_h2"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("phase0_harness_h2", None)
        raise
    return module


h2 = _load_h2()
h1 = h2.h1

AbortRun = h1.AbortRun
HarnessError = h1.HarnessError
SensitiveValue = h1.SensitiveValue
SCOPE = h1.SCOPE
EXTRA_SCOPE = h1.EXTRA_SCOPE
TENANT = h1.TENANT
parse_json = h1.parse_json

# ---------------------------------------------------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------------------------------------------------

PACKAGE = "H-6"
EVENT_PREFIX = "h6_"
REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
SERVER_DIR = os.path.join(REPO_ROOT, "server")
JAR_PATH = os.path.join(SERVER_DIR, "target", "iam-service-1.0.0.jar")
POLICY_CONFIG = os.path.join(REPO_ROOT, "platform-policy", "config.yaml")
POLICY_BASE = os.path.join(REPO_ROOT, "platform-policy", "policies")
PLATFORM_CONTRACT = os.path.join(REPO_ROOT, "platform-contract", "axiom-platform-contract.json")
JAVA_HOME = "/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home"
JAVA = os.path.join(JAVA_HOME, "bin", "java")
POSTGRES_IMAGE = "postgres:16"
REDIS_IMAGE = "redis:7-alpine"
# The chart pins cerbos 0.53.0; only this tag is available offline. Recorded in every run as a deviation.
CERBOS_IMAGE = "ghcr.io/cerbos/cerbos:latest"
LABEL_KEY = "axiom.phase0.h6"
# Mirrors deploy/phase0-isolated/values.yaml (config.approvedBusinessScopes and bootstrap.*).
APPROVED_SCOPES = "cards:incident.read,cards:freeze.propose,wealth:review.invoke,quickstart:invoke"
BOOTSTRAP = {"AXIOM_BOOTSTRAP_TENANT_ID": TENANT, "AXIOM_BOOTSTRAP_TENANT_NAME": "Meridian Phase 0 Local H-6",
             "AXIOM_BOOTSTRAP_TENANT_SLUG": TENANT, "AXIOM_BOOTSTRAP_ADMIN_ID": h1.ADMIN_USERNAME,
             "AXIOM_BOOTSTRAP_ADMIN_USERNAME": h1.ADMIN_USERNAME,
             "AXIOM_BOOTSTRAP_ADMIN_EMAIL": f"{h1.ADMIN_USERNAME}@phase0.invalid"}
# Every VOLUME declared by the images (docker image inspect .Config.Volumes), mounted as labelled named volumes.
IMAGE_VOLUMES = {"postgres": ("/var/lib/postgresql/data",), "redis": ("/data",),
                 "cerbos": ("/.cache", "/tmp", "/policies")}
SECRET_FILES = ("spring.datasource.password", "iam.secrets.master-key", "axiom.bootstrap.admin-password")
DOCKER_TIMEOUT = 60.0
READY_TIMEOUT = 90.0
BOOTSTRAP_TIMEOUT = 180.0
STOP_TIMEOUT = 20.0
DEVIATIONS = (
    "local disposable stack from the current clone instead of the axiom-phase0-test release (image 74e7e56)",
    "issuer is http://127.0.0.1:<port> instead of the in-cluster service URL",
    "signing key generated at startup (release mounts a provisioned key)",
    "cerbos image ghcr.io/cerbos/cerbos:latest (chart pins 0.53.0)",
    "secrets via configtree files in a 0700 temporary directory (release: Kubernetes Secret volume)",
)
ROUTE_CLAIM = ("R1-R4 are H-2 fixture routes; results prove Axiom edge semantics for these fixture routes only and "
               "do not claim Phase 1 provisions R2, R3 or R4")

# ---------------------------------------------------------------------------------------------------------------------
# Expectation table: H-2 cases unchanged, plus broker-edge denials
# ---------------------------------------------------------------------------------------------------------------------

def _deny(cls: str, requester: str, subject: str, audience: str, scope: str, status: int, error: str,
          description: str) -> dict:
    return {"class": cls, "kind": "exchange", "requester": requester, "subject": subject, "audience": audience,
            "scope": scope, "depends": [subject], "description": description,
            "denial": {"status": status, "error": error}}


H6_CASES: dict = {
    # --- broker -> Agent edge (R2). Subjects: P3 = BFF gateway_authorization for the broker; P2/P4 other uses.
    "H6-A1": _deny("wrong_token_use", "broker", "H2-P2", "{agent_aud}", SCOPE, 400, "invalid_grant",
                   "broker presents P2 (workforce exchange_subject for the BFF) to agent aud: invalid_grant"),
    "H6-A2": _deny("wrong_redeemer", "agent", "H2-P3", "{agent_aud}", SCOPE, 400, "invalid_grant",
                   "destination Agent redeems P3 (addressed to the broker) to its own aud: invalid_grant"),
    "H6-A3": _deny("wrong_redeemer", "sibling", "H2-P3", "{agent_aud}", SCOPE, 400, "invalid_grant",
                   "unrelated workload <p>-sibling redeems P3 to agent aud: invalid_grant"),
    "H6-A4": _deny("wrong_redeemer", "bff", "H2-P3", "{agent_aud}", SCOPE, 400, "invalid_grant",
                   "source BFF redeems its own P3 to agent aud (bypassing the broker): invalid_grant"),
    "H6-A5": _deny("over_broad_scope", "broker", "H2-P3", "{agent_aud}", f"{SCOPE} {EXTRA_SCOPE}", 400,
                   "invalid_scope", "broker exchanges P3 to agent aud with an extra scope: invalid_scope"),
    "H6-A6": _deny("wrong_destination", "broker", "H2-P3", "{sibling_aud}", SCOPE, 400, "invalid_target",
                   "broker exchanges P3 to sibling aud (registered workload, no BFF route): invalid_target"),
    "H6-A7": _deny("wrong_destination", "broker", "H2-P3", "{gateway_aud}", SCOPE, 400, "invalid_target",
                   "broker exchanges P3 back to the gateway aud (R1 is a GATEWAY route): invalid_target"),
    "H6-A8": _deny("wrong_destination", "broker", "H2-P3", "{tool_aud}", SCOPE, 400, "invalid_target",
                   "broker exchanges P3 to tool aud (R4 belongs to the Agent, not the BFF): invalid_target"),
    "H6-A9": _deny("wrong_token_use", "broker", "H2-P4", "{agent_aud}", SCOPE, 400, "invalid_grant",
                   "broker re-presents its own P4 (gateway_backend exchange_subject) to agent aud: invalid_grant"),
    # --- broker -> resource edge (R4). Subjects: P5 = Agent gateway_authorization for the broker; P6 delegated.
    "H6-R1": _deny("wrong_redeemer", "agent", "H2-P5", "{tool_aud}", SCOPE, 400, "invalid_grant",
                   "Agent redeems its own P5 to tool aud (bypassing the broker): invalid_grant"),
    "H6-R2": _deny("wrong_redeemer", "bff", "H2-P5", "{tool_aud}", SCOPE, 400, "invalid_grant",
                   "BFF redeems P5 (Agent's gateway token) to tool aud: invalid_grant"),
    "H6-R3": _deny("over_broad_scope", "broker", "H2-P5", "{tool_aud}", f"{SCOPE} {EXTRA_SCOPE}", 400,
                   "invalid_scope", "broker exchanges P5 to tool aud with an extra scope: invalid_scope"),
    "H6-R4": _deny("wrong_destination", "broker", "H2-P5", "{sibling_aud}", SCOPE, 400, "invalid_target",
                   "broker exchanges P5 to sibling aud (no Agent route): invalid_target"),
    "H6-R5": _deny("wrong_destination", "broker", "H2-P5", "{agent_aud}", SCOPE, 400, "invalid_target",
                   "broker exchanges P5 to the Agent's own aud (no Agent -> Agent route): invalid_target"),
    "H6-R6": _deny("wrong_token_use", "broker", "H2-P6", "{tool_aud}", SCOPE, 400, "invalid_grant",
                   "broker re-presents P6 (delegated_access resource token) to tool aud: invalid_grant"),
    "H6-R7": _deny("wrong_token_use", "broker", "H2-P4", "{tool_aud}", SCOPE, 400, "invalid_grant",
                   "broker presents P4 (exchange_subject for the Agent) to tool aud: invalid_grant"),
}


def build_expectations() -> dict:
    table = copy.deepcopy(h2.H2_EXPECTATIONS)
    order = list(table["order"])

    def insert_after(anchor: str, ids: list[str]) -> None:
        i = order.index(anchor) + 1
        order[i:i] = ids

    # Denials on P3 run before H2-P4 uses P3; denials on P4 run before H2-P5; on P5 before H2-P6; on P6 last.
    insert_after("H2-N8", ["H6-A1", "H6-A2", "H6-A3", "H6-A4", "H6-A5", "H6-A6", "H6-A7", "H6-A8"])
    insert_after("H2-P4", ["H6-A9", "H6-R7"])
    insert_after("H2-N9", ["H6-R1", "H6-R2", "H6-R3", "H6-R4", "H6-R5"])
    order.append("H6-R6")
    table["order"] = order
    table["cases"].update(copy.deepcopy(H6_CASES))
    h2.validate_expectations(table)
    return table


H6_EXPECTATIONS = build_expectations()

# ---------------------------------------------------------------------------------------------------------------------
# Disposable local stack
# ---------------------------------------------------------------------------------------------------------------------

def _refuse_cluster_tools(argv: list[str]) -> None:
    if argv and os.path.basename(str(argv[0])) in ("kubectl", "helm"):
        raise HarnessError("H-6 never invokes kubectl or helm")


def default_run(argv: list[str], timeout: float, env: dict | None = None) -> subprocess.CompletedProcess:
    _refuse_cluster_tools(argv)
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, check=False)


def newest_mtime(root: str) -> float:
    newest = 0.0
    for d, _dirs, files in os.walk(root):
        for f in files:
            newest = max(newest, os.path.getmtime(os.path.join(d, f)))
    return newest


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class LocalStack:
    """Containers, work directory, bootstrap job and server process for one run. Every resource is labelled or
    owned by this object and removed by ``teardown``."""

    def __init__(self, prefix: str, *, run: Callable = default_run, popen: Callable = subprocess.Popen,
                 workdir_parent: str | None = None, monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.prefix = prefix
        self.label = f"{LABEL_KEY}={prefix}"
        self.run = run
        self.popen = popen
        self.workdir_parent = workdir_parent
        self.monotonic = monotonic
        self.sleep = sleep
        self.docker = shutil.which("docker") or "docker"
        self.workdir: str | None = None
        self.containers: dict[str, str] = {}
        self.ports: dict[str, int] = {}
        self.server: Any = None
        self.bootstrap_proc: Any = None
        self.server_port: int | None = None
        self.issuer: str | None = None
        self.teardown_result: dict | None = None

    # -- paths ----------------------------------------------------------------------------------------------------
    def path(self, *parts: str) -> str:
        assert self.workdir is not None
        return os.path.join(self.workdir, *parts)

    # -- preparation ----------------------------------------------------------------------------------------------
    def tool_evidence(self) -> dict:
        java = self.run([JAVA, "-version"], 30.0)
        docker = self.run([self.docker, "version", "--format", "{{.Server.Version}}"], 30.0)
        jar_ok = os.path.isfile(JAR_PATH)
        jar_mtime = os.path.getmtime(JAR_PATH) if jar_ok else None
        src_mtime = newest_mtime(os.path.join(SERVER_DIR, "src", "main"))
        java_text = (java.stderr or "") + (java.stdout or "")
        images = {}
        for image in (POSTGRES_IMAGE, REDIS_IMAGE, CERBOS_IMAGE):
            r = self.run([self.docker, "image", "inspect", "--format", "{{.Id}}", image], 30.0)
            images[image] = (r.stdout or "").strip() if r.returncode == 0 else None
        return {
            "java_25": java.returncode == 0 and 'version "25' in java_text,
            "docker_server": (docker.stdout or "").strip() if docker.returncode == 0 else None,
            "jar": os.path.relpath(JAR_PATH, REPO_ROOT), "jar_sha256": sha256_file(JAR_PATH) if jar_ok else None,
            "jar_newer_than_sources": jar_ok and jar_mtime is not None and jar_mtime >= src_mtime,
            "images": images,
        }

    def make_workdir(self) -> dict:
        # The path is recorded before the directory exists, so teardown can always remove it.
        parent = self.workdir_parent or tempfile.gettempdir()
        self.workdir = os.path.join(parent, f"axiom-h6-{self.prefix}-{secrets.token_hex(4)}")
        os.mkdir(self.workdir, 0o700)
        os.chmod(self.workdir, 0o700)
        for sub in ("secrets", "keys", "staging", "runtime"):
            os.mkdir(self.path(sub), 0o700)
        os.chmod(self.path("runtime"), 0o777)  # written by the Cerbos container user, never holds secrets
        values = {
            "spring.datasource.password": secrets.token_urlsafe(24),
            "iam.secrets.master-key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "axiom.bootstrap.admin-password": secrets.token_urlsafe(24) + "Aa1!",
        }
        for name, value in values.items():
            fd = os.open(self.path("secrets", name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(value)
        modes = {name: oct(os.stat(self.path("secrets", name)).st_mode & 0o777) for name in SECRET_FILES}
        return {"workdir_mode": oct(os.stat(self.workdir).st_mode & 0o777), "secret_file_modes": modes}

    def secret(self, name: str) -> str:
        with open(self.path("secrets", name), encoding="utf-8") as fh:
            return fh.read()

    # -- containers -----------------------------------------------------------------------------------------------
    def _volume_mounts(self, role: str, paths: tuple[str, ...]) -> list[str]:
        """Named, labelled volumes for every image VOLUME path, so teardown can find and remove them by label even
        when the container is already gone (anonymous volumes carry no label)."""
        args: list[str] = []
        for i, dst in enumerate(paths):
            name = f"axiom-h6-{self.prefix}-{role}-{i}"
            args += ["--mount", f"type=volume,src={name},dst={dst},volume-label={self.label}"]
        return args

    def _docker_run(self, role: str, args: list[str]) -> str:
        argv = [self.docker, "run", "-d", "--rm", "--label", self.label, "--label", f"{LABEL_KEY}.role={role}",
                *self._volume_mounts(role, IMAGE_VOLUMES[role]), *args]
        r = self.run(argv, DOCKER_TIMEOUT)
        cid = (r.stdout or "").strip()
        if r.returncode != 0 or not cid:
            raise AbortRun(f"container {role} did not start")
        self.containers[role] = cid
        return cid

    def _port(self, role: str, container_port: int) -> int:
        r = self.run([self.docker, "port", self.containers[role], f"{container_port}/tcp"], DOCKER_TIMEOUT)
        line = (r.stdout or "").strip().splitlines()[0] if r.returncode == 0 and (r.stdout or "").strip() else ""
        host, _, port = line.rpartition(":")
        if host != "127.0.0.1" or not port.isdigit():
            raise AbortRun(f"container {role} port {container_port} not bound to 127.0.0.1")
        return int(port)

    def start_containers(self) -> dict:
        pw = self.path("secrets", "spring.datasource.password")
        self._docker_run("postgres", ["-e", "POSTGRES_USER=axiom", "-e", "POSTGRES_DB=axiom",
                                      "-e", "POSTGRES_PASSWORD_FILE=/run/axiom/db-password",
                                      "-v", f"{pw}:/run/axiom/db-password:ro", "-p", "127.0.0.1::5432",
                                      POSTGRES_IMAGE])
        self._docker_run("redis", ["-p", "127.0.0.1::6379", REDIS_IMAGE])
        self._docker_run("cerbos", ["-v", f"{POLICY_CONFIG}:/conf/config.yaml:ro",
                                    "-v", f"{POLICY_BASE}:/policies/base:ro",
                                    "-v", f"{self.path('runtime')}:/policies/runtime",
                                    "--tmpfs", "/var/log/cerbos", "-p", "127.0.0.1::3592", "-p", "127.0.0.1::3593",
                                    CERBOS_IMAGE, "server", "--config=/conf/config.yaml"])
        self.ports = {"postgres": self._port("postgres", 5432), "redis": self._port("redis", 6379),
                      "cerbos_http": self._port("cerbos", 3592), "cerbos_grpc": self._port("cerbos", 3593)}
        deadline = self.monotonic() + READY_TIMEOUT
        pg_ready = False
        while self.monotonic() < deadline:
            logs = self.run([self.docker, "logs", self.containers["postgres"]], DOCKER_TIMEOUT)
            text = (logs.stdout or "") + (logs.stderr or "")
            if text.count("database system is ready to accept connections") >= 2:
                pg_ready = True
                break
            self.sleep(1.0)
        if not pg_ready:
            raise AbortRun("postgres not ready")
        return {"containers": {k: v[:12] for k, v in self.containers.items()}, "ports": self.ports,
                "bound_to": "127.0.0.1"}

    # -- server ---------------------------------------------------------------------------------------------------
    def server_env(self, issuer: str) -> dict:
        env = {"PATH": "/usr/bin:/bin", "HOME": self.path(), "LANG": "C.UTF-8", "TMPDIR": self.path(),
               "JAVA_HOME": JAVA_HOME,
               "SPRING_DATASOURCE_URL": f"jdbc:postgresql://127.0.0.1:{self.ports['postgres']}/axiom",
               "SPRING_DATASOURCE_USERNAME": "axiom",
               "SPRING_CONFIG_IMPORT": f"configtree:{self.path('secrets')}/",
               "SPRING_DATA_REDIS_HOST": "127.0.0.1", "SPRING_DATA_REDIS_PORT": str(self.ports["redis"]),
               "IAM_ISSUER_URL": issuer,
               "IAM_SIGNING_KEY_PATH": self.path("keys", "signing-key.json"),
               "IAM_SIGNING_KEY_ALLOW_GENERATION": "true",
               "IAM_OAUTH2_APPROVED_BUSINESS_SCOPES": APPROVED_SCOPES,
               "CERBOS_HOST": "127.0.0.1", "CERBOS_PORT": str(self.ports["cerbos_grpc"]),
               "CERBOS_HTTP_PORT": str(self.ports["cerbos_http"]),
               "IAM_POLICY_STUDIO_BASE_BUNDLE_DIR": POLICY_BASE,
               "IAM_POLICY_STUDIO_PLATFORM_CONTRACT_PATH": PLATFORM_CONTRACT,
               "IAM_TENANCY_POLICY_STAGING_DIR": self.path("staging"),
               "IAM_POLICY_STUDIO_RUNTIME_POLICIES_DIR": self.path("runtime")}
        return env

    def bootstrap(self, issuer: str) -> dict:
        env = {**self.server_env(issuer), "AXIOM_BOOTSTRAP_ENABLED": "true", **BOOTSTRAP}
        with open(self.path("bootstrap.log"), "w") as log:
            # Spawn and record under deferred signals, so teardown always knows the process.
            blocked = _block_signals()
            try:
                proc = self.popen([JAVA, "-jar", JAR_PATH, "--spring.main.web-application-type=none"],
                                  cwd=self.path(), env=env, stdout=log, stderr=subprocess.STDOUT)
                self.bootstrap_proc = proc
            finally:
                _restore_signals(blocked)
            try:
                rc = proc.wait(timeout=BOOTSTRAP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._stop_process(proc)
                rc = None
        if proc.poll() is not None:
            self.bootstrap_proc = None
        return {"exit_code": rc}

    def start_server(self, port: int, issuer: str) -> None:
        self.server_port = port
        self.issuer = issuer
        log = open(self.path("server.log"), "w")
        blocked = _block_signals()
        try:
            self.server = self.popen([JAVA, "-jar", JAR_PATH, "--server.address=127.0.0.1", f"--server.port={port}"],
                                     cwd=self.path(), env=self.server_env(issuer), stdout=log,
                                     stderr=subprocess.STDOUT)
        finally:
            log.close()
            _restore_signals(blocked)

    def server_alive(self) -> bool:
        return self.server is not None and self.server.poll() is None

    def log_tail(self, name: str, n: int = 15) -> list[str]:
        try:
            with open(self.path(name), encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return []
        keep = [l for l in lines if "ERROR" in l or "Caused by" in l or "FAIL" in l]
        return [l[:240] for l in (keep or lines)[-n:]]

    # -- teardown -------------------------------------------------------------------------------------------------
    @staticmethod
    def _stop_process(proc: Any) -> bool:
        """terminate, then kill; True once the process has exited."""
        if proc is None:
            return True
        for action in ("terminate", "kill"):
            if proc.poll() is not None:
                return True
            try:
                getattr(proc, action)()
                proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                continue
            except ProcessLookupError:
                pass
        return proc.poll() is not None

    def _labelled(self, kind: str) -> list[str] | None:
        """Ids of this run's containers (kind="container") or volumes (kind="volume"); None if docker failed."""
        argv = ([self.docker, "ps", "-aq", "--filter", f"label={self.label}"] if kind == "container"
                else [self.docker, "volume", "ls", "-q", "--filter", f"label={self.label}"])
        r = self.run(argv, DOCKER_TIMEOUT)
        if r.returncode != 0:
            return None
        return [l for l in (r.stdout or "").split() if l]

    def teardown(self) -> dict:
        """Idempotent. Stops processes, removes only resources labelled with this run's prefix and the work
        directory. Every step runs even if an earlier one fails or a signal arrives; delivery of SIGINT/SIGTERM/SIGHUP
        is deferred while it runs, and an interruption that still lands is recorded instead of escaping."""
        if self.teardown_result is not None:
            return self.teardown_result
        result: dict = {"server_exited": True, "bootstrap_exited": True, "containers_removed": 0,
                        "containers_remaining": None, "volumes_removed": 0, "volumes_remaining": None,
                        "workdir_removed": True, "interrupted": False, "docker_timeouts": 0, "errors": []}
        blocked = _block_signals()
        try:
            def step(name: str, fn: Callable[[], None]) -> None:
                try:
                    fn()
                except KeyboardInterrupt:
                    result["interrupted"] = True
                    result["errors"].append(f"{name}: interrupted")
                except BaseException as exc:  # noqa: BLE001 - never skip the remaining steps; type only
                    result["errors"].append(f"{name}: {type(exc).__name__}")

            def stop_processes() -> None:
                result["bootstrap_exited"] = self._stop_process(self.bootstrap_proc)
                result["server_exited"] = self._stop_process(self.server)

            def remove(kind: str) -> None:
                key = "containers" if kind == "container" else "volumes"
                for _attempt in range(3):
                    try:
                        ids = self._labelled(kind)
                        if ids is None:
                            continue
                        if not ids:
                            result[f"{key}_remaining"] = 0
                            return
                        argv = ([self.docker, "rm", "-f", "-v", *ids] if kind == "container"
                                else [self.docker, "volume", "rm", "-f", *ids])
                        if self.run(argv, DOCKER_TIMEOUT).returncode == 0:
                            result[f"{key}_removed"] += len(ids)
                    except KeyboardInterrupt:
                        result["interrupted"] = True
                    except subprocess.TimeoutExpired:
                        result["docker_timeouts"] += 1  # retried; the final listing decides the outcome
                after = self._labelled(kind)
                result[f"{key}_remaining"] = None if after is None else len(after)

            def remove_workdir() -> None:
                if self.workdir is not None:
                    shutil.rmtree(self.workdir, ignore_errors=True)
                    result["workdir_removed"] = not os.path.exists(self.workdir)

            step("processes", stop_processes)
            step("containers", lambda: remove("container"))
            # Volumes after containers: a volume cannot be removed while a container still uses it.
            step("volumes", lambda: remove("volume"))
            step("workdir", remove_workdir)
            result["ok"] = (result["server_exited"] and result["bootstrap_exited"]
                            and result["containers_remaining"] == 0 and result["volumes_remaining"] == 0
                            and result["workdir_removed"] and not result["errors"])
            self.teardown_result = result
        finally:
            try:
                # A signal deferred during teardown is delivered here; record it rather than lose the result.
                _restore_signals(blocked)
            except KeyboardInterrupt:
                result["interrupted"] = True
        return result


_TEARDOWN_SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def _block_signals() -> Any:
    try:
        return signal.pthread_sigmask(signal.SIG_BLOCK, _TEARDOWN_SIGNALS)
    except (AttributeError, ValueError, OSError):
        return None


def _restore_signals(previous: Any) -> None:
    if previous is not None:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except (AttributeError, ValueError, OSError):
            pass


# ---------------------------------------------------------------------------------------------------------------------
# Runner: H-2 cases and setup over the local stack
# ---------------------------------------------------------------------------------------------------------------------

class H6Runner(h2.H2Runner):
    def __init__(self, *, stack_factory: Callable[[str], LocalStack] = LocalStack, **kw: Any):
        kw.setdefault("expectations", H6_EXPECTATIONS)
        super().__init__(run_cmd=self._no_cluster_cmd, popen=self._no_cluster_popen, **kw)
        self.stack = stack_factory(self.prefix)
        self.issuer: str | None = None
        self.teardown_result: dict | None = None

    @staticmethod
    def _no_cluster_cmd(argv: list[str], timeout: float) -> Any:
        raise HarnessError("H-6 never runs kubectl/helm")

    @staticmethod
    def _no_cluster_popen(argv: list[str]) -> Any:
        raise HarnessError("H-6 never runs kubectl port-forward")

    # -- output -----------------------------------------------------------------------------------------------------
    def emit(self, event: dict) -> None:
        ev = dict(event)
        name = str(ev.get("event", ""))
        if name.startswith(h2.EVENT_PREFIX):
            name = name[len(h2.EVENT_PREFIX):]
        ev["event"] = name if name.startswith(EVENT_PREFIX) else EVENT_PREFIX + name
        ev["package"] = PACKAGE
        if name == "run_start":
            ev["context"] = "local-disposable"
            ev["namespace"] = None
            ev["deviations"] = list(DEVIATIONS)
            ev["route_claim"] = ROUTE_CLAIM
        if name == "summary":
            ev["teardown"] = self.teardown_result
            ev["route_claim"] = ROUTE_CLAIM
        h1.Runner.emit(self, ev)

    # -- teardown guarantees ----------------------------------------------------------------------------------------
    # H-2's run() calls V-1..V-6 outside the try/finally that reaches stop_port_forward(), so each of those steps
    # tears the stack down itself before propagating any failure or interruption. run() adds a final net for an
    # interruption that lands between steps or after H-2's own handlers.
    def _teardown_on_failure(self, fn: Callable[[], None]) -> None:
        try:
            fn()
        except BaseException:
            self.stop_port_forward()
            raise

    def v1_context(self) -> None:
        self._teardown_on_failure(self._l1_tools)

    def v2_namespace(self) -> None:
        self._teardown_on_failure(self._l2_workdir)

    def v3_release(self) -> None:
        self._teardown_on_failure(self._l3_containers)

    def v4_pod(self) -> None:
        self._teardown_on_failure(self._l4_no_cluster)

    def v5_secret(self) -> None:
        self._teardown_on_failure(self._l5_admin_password)

    def v6_port(self) -> None:
        self._teardown_on_failure(super().v6_port)

    def run(self) -> int:
        rc = 2
        try:
            rc = super().run()
        except BaseException as exc:  # noqa: BLE001 - e.g. a signal while the summary is written
            if not self.aborted:
                self.aborted = True
                self.abort_reason = f"{type(exc).__name__} outside the run handlers"
        finally:
            late = self.teardown_result is None
            if late:
                try:
                    self.stop_port_forward()
                except BaseException:  # noqa: BLE001
                    self.pf_leaked = True
        if late or self.teardown_result is None or not self.teardown_result.get("ok"):
            rc = 2
        return rc

    # -- local verification steps (replace H-1 V-1..V-5) -------------------------------------------------------------
    def _l1_tools(self) -> None:
        evidence = self.stack.tool_evidence()
        ok = (evidence["java_25"] and evidence["docker_server"] is not None and evidence["jar_sha256"] is not None
              and evidence["jar_newer_than_sources"] and all(evidence["images"].values()))
        self._verify("L-1 tools, images and current-source jar", ok, **evidence)

    def _l2_workdir(self) -> None:
        detail = self.stack.make_workdir()
        self.redactor.register(self.stack.secret("spring.datasource.password"))
        self.redactor.register(self.stack.secret("iam.secrets.master-key"))
        ok = detail["workdir_mode"] == "0o700" and all(m == "0o600" for m in detail["secret_file_modes"].values())
        self._verify("L-2 private work directory and generated secrets", ok, **detail)

    def _l3_containers(self) -> None:
        self._verify("L-3 disposable containers", True, **self.stack.start_containers())

    def _l4_no_cluster(self) -> None:
        # The bootstrap job needs the issuer, which depends on the port chosen in V-6; it runs in start_port_forward.
        self._verify("L-4 no cluster access", True, kubectl_or_helm_invoked=False)

    def _l5_admin_password(self) -> None:
        self.admin_password = self._sensitive(self.stack.secret("axiom.bootstrap.admin-password"))
        self._verify("L-5 bootstrap admin password (local configtree file)", True, source="configtree file")

    def start_port_forward(self) -> None:
        self.issuer = f"http://127.0.0.1:{self.port}"
        self.env.variables["issuer"] = self.issuer
        result = self.stack.bootstrap(self.issuer)
        if result["exit_code"] != 0:
            self.emit({"event": "verify", "step": "L-6 bootstrap job", "ok": False, **result,
                       "log_tail": self.stack.log_tail("bootstrap.log")})
            raise AbortRun("bootstrap failed")
        self._verify("L-6 bootstrap job", True, **result)
        self.stack.start_server(self.port, self.issuer)
        self.pf = self.stack.server
        deadline = self.monotonic() + READY_TIMEOUT
        while self.monotonic() < deadline and self.stack.server_alive():
            try:
                status, _ = self.request("GET", "/actuator/health/readiness", abort_on_5xx=False)
            except AbortRun:
                status = None
            if status == 200:
                break
            time.sleep(1.0)
        ready = self.stack.server_alive()
        self.emit({"event": "server_start", "ok": ready, "port": self.port, "issuer": self.issuer})
        if not ready:
            self.emit({"event": "server_log", "log_tail": self.stack.log_tail("server.log")})
            raise AbortRun("server not started")

    def _pf_alive(self) -> bool:
        return self.stack.server_alive()

    def request_full(self, method: str, path: str, **kw: Any) -> Any:
        try:
            return super().request_full(method, path, **kw)
        except AbortRun as exc:
            # Only the readiness poll tolerates a refused connection while the server starts.
            if path == "/actuator/health/readiness" and "transport error" in str(exc):
                return None, [], None
            raise

    def _restart_port_forward_for_cleanup(self) -> bool:
        return False

    def stop_port_forward(self) -> None:
        """Idempotent: the stack is torn down and reported exactly once, whichever path reaches it first."""
        if self.teardown_result is not None:
            return
        result = self.stack.teardown()
        self.teardown_result = result
        if not result["ok"]:
            self.pf_leaked = True
        if result["interrupted"] and not self.aborted:
            self._abort("interrupted during teardown")
        self.emit({"event": "teardown", **result})

    # -- discovery and admin login with the local issuer (H-1 V-7/V-9 assert the in-cluster issuer) ------------------
    def v7_discovery(self) -> None:
        status, raw = self.request("GET", "/.well-known/openid-configuration")
        doc = parse_json(raw)
        doc = doc if isinstance(doc, dict) else {}
        m_status, m_raw = self.request("GET", "/.well-known/oauth-authorization-server")
        meta = parse_json(m_raw)
        meta = meta if isinstance(meta, dict) else {}
        grants = meta.get("grant_types_supported")
        exchange_ok = isinstance(grants, list) and h1.TOKEN_EXCHANGE_GRANT in grants
        ok = (status == 200 and doc.get("issuer") == self.issuer and m_status == 200
              and meta.get("issuer") == self.issuer and exchange_ok)
        self._verify("V-7", ok, status=status, issuer=doc.get("issuer"), metadata_status=m_status,
                     metadata_issuer=meta.get("issuer"), token_exchange_supported=exchange_ok)

    def v9_login(self) -> None:
        status, raw = self.request("POST", "/auth/login", json_body={"username": h1.ADMIN_USERNAME,
                                                                    "password": self.admin_password.reveal()})
        doc = parse_json(raw)
        doc = doc if isinstance(doc, dict) else {}
        token = doc.get("accessToken")
        claims: dict = {}
        if isinstance(token, str) and token:
            self.redactor.register(token)
            try:
                _h, claims = h1.decode_jwt(token)
            except ValueError:
                claims = {}
        for k in ("refreshToken", "refresh_token", "sessionToken"):
            if isinstance(doc.get(k), str):
                self.redactor.register(doc[k])
        roles = h1.normalize_roles(claims.get("roles"))
        ok = (status == 200 and claims.get("iss") == self.issuer and claims.get("tenant_id") == TENANT
              and h1.normalize_aud(claims.get("aud")) == [h1.ADMIN_AUDIENCE] and h1.ADMIN_ROLE in roles)
        if ok:
            self.admin_token = SensitiveValue(token)
        self._verify("V-9", ok, status=status, iss=claims.get("iss"), tenant_id=claims.get("tenant_id"),
                     aud=claims.get("aud"), platform_admin=h1.ADMIN_ROLE in roles,
                     token_sha256_12=h1.token_hash(token) if isinstance(token, str) else None)


# ---------------------------------------------------------------------------------------------------------------------
# Plan mode and CLI
# ---------------------------------------------------------------------------------------------------------------------

def plan_events() -> list[dict]:
    events: list[dict] = [{"event": "h6_plan", "package": PACKAGE, "mode": "dry",
                           "note": "no subprocess, container or network activity; pass --execute to run",
                           "h2_sha256": H2_SHA256, "jar": os.path.relpath(JAR_PATH, REPO_ROOT),
                           "images": [POSTGRES_IMAGE, REDIS_IMAGE, CERBOS_IMAGE], "deviations": list(DEVIATIONS),
                           "route_claim": ROUTE_CLAIM}]
    for ev in h2.plan_events(H6_EXPECTATIONS):
        name = str(ev.get("event", ""))
        if name in ("h2_plan", "h2_plan_verify"):
            continue
        ev = {**ev, "event": EVENT_PREFIX + name[len(h2.EVENT_PREFIX):], "package": PACKAGE}
        if ev.get("case_id", "").startswith("H6-"):
            ev["added_by"] = PACKAGE
        events.append(ev)
    events.append({"event": "h6_plan_teardown", "package": PACKAGE,
                   "order": ["stop bootstrap job and server (terminate, then kill)",
                             "docker rm -f -v containers labelled " + LABEL_KEY + "=<p>",
                             "docker volume rm -f volumes labelled " + LABEL_KEY + "=<p>",
                             "remove work directory (secrets, keys, staging, runtime policies, logs)"],
                   "guarantee": "runs once on every exit path, including failures in L-1..L-6/V-6 and interruption; "
                                "signals are deferred while it runs; only this run's labelled resources are removed"})
    return events


def main(argv: list[str] | None = None, *, out: Any = None,
         runner_factory: Callable[..., H6Runner] = H6Runner) -> int:
    out = out if out is not None else sys.stdout
    if sys.version_info < (3, 13):
        sys.stderr.write("phase0_harness_h6_broker_edges requires Python 3.13+\n")
        return 2
    parser = argparse.ArgumentParser(description="Phase 0.2 H-6 broker-edge harness on a disposable local stack")
    parser.add_argument("--package", required=True, choices=("h6",), help="test package to run (h6 only)")
    parser.add_argument("--execute", action="store_true", help="build the local stack and run")
    args = parser.parse_args(argv)
    if not args.execute:
        for ev in plan_events():
            out.write(json.dumps(ev) + "\n")
        return 0

    def _interrupt(signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _interrupt)
    return runner_factory(out=out).run()


if __name__ == "__main__":
    sys.exit(main())
