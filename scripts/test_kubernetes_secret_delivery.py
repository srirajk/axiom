#!/usr/bin/env python3
"""Offline tests for credential delivery to Kubernetes Secrets (Phase 1.2).

Covers scripts/configure_axiom.py (reveal-once OAuth client secrets) and
deploy/helm/axiom/scripts/create-signing-secret.py (signing JWK). kubectl is replaced by an in-memory fake API
server; nothing touches a cluster, Axiom or the network. openssl runs locally for real key generation.

    python3 -B scripts/test_kubernetes_secret_delivery.py
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


configure = _load("configure_axiom", ROOT / "scripts" / "configure_axiom.py")
signing = _load("create_signing_secret", ROOT / "deploy" / "helm" / "axiom" / "scripts" / "create-signing-secret.py")

LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"


class FakeKubectl:
    """Minimal Secret API. ``apply`` and ``create --save-config`` record the last-applied annotation exactly as the
    real client does, so a regression to either is visible. ``faults[verb]`` may return a CompletedProcess to
    replace the call, optionally after letting it take effect."""

    def __init__(self, real_run):
        self.real_run = real_run
        self.secrets: dict[tuple[str, str], dict] = {}
        self.calls: list[dict] = []
        self.faults: dict = {}
        self.inputs_seen_at_create: list = []
        self.on_create = None
        self.next_version = 1

    def __call__(self, argv, input=None, text=False, check=False, capture_output=False, stdout=None,
                 stderr=None, **kw):
        argv = list(argv)
        if argv[0] != "kubectl":
            return self.real_run(argv, input=input, text=text, check=check, capture_output=capture_output,
                                 stdout=stdout, stderr=stderr, **kw)
        raw = input.decode() if isinstance(input, bytes) else input
        self.calls.append({"argv": argv, "stdin": raw})
        result = self._handle(argv, raw)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, argv, result.stdout, result.stderr)
        if text is False and isinstance(result.stdout, str):
            result = subprocess.CompletedProcess(argv, result.returncode, result.stdout.encode(),
                                                 result.stderr.encode())
        return result

    @staticmethod
    def done(argv, rc=0, out="", err=""):
        return subprocess.CompletedProcess(argv, rc, out, err)

    def _handle(self, argv, raw):
        verb = argv[1]
        if argv[1:3] == ["auth", "can-i"]:
            return self.done(argv, out="yes\n")
        if verb in ("create", "apply", "replace"):
            manifest = json.loads(raw)
            meta = manifest["metadata"]
            key = (meta["namespace"], meta["name"])
            dry = "--dry-run=server" in argv
            fault = self.faults.get(("create", "dry" if dry else "real"))
            if fault is not None:
                replaced = fault(self, argv, manifest)
                if replaced is not None:
                    return replaced
            if verb == "replace":
                if key not in self.secrets:
                    return self.done(argv, 1, err=f'Error from server (NotFound): secrets "{key[1]}" not found')
                if meta.get("resourceVersion") != self.secrets[key]["metadata"].get("resourceVersion"):
                    return self.done(argv, 1, err=f'Error from server (Conflict): secrets "{key[1]}" changed')
                self.store(manifest)
                return self.done(argv, out=f"secret/{key[1]} replaced\n")
            if verb == "create" and key in self.secrets:
                return self.done(argv, 1, err=f'Error from server (AlreadyExists): secrets "{key[1]}" already exists')
            if dry:
                return self.done(argv, out=f"secret/{key[1]}\n")
            if self.on_create:
                self.on_create(self, key)
            self.store(manifest, annotate=(verb == "apply" or "--save-config" in argv))
            return self.done(argv, out=f"secret/{key[1]} created\n")
        if verb == "get" and argv[2] == "secret":
            name, namespace = argv[3], argv[argv.index("-n") + 1]
            obj = self.secrets.get((namespace, name))
            if obj is None:
                if "--ignore-not-found" in argv:
                    return self.done(argv)
                return self.done(argv, 1, err=f'Error from server (NotFound): secrets "{name}" not found')
            return self.done(argv, out=json.dumps(obj))
        raise AssertionError(f"unexpected kubectl call {argv}")

    def store(self, manifest, annotate=False):
        meta = dict(manifest["metadata"])
        meta["resourceVersion"] = str(self.next_version)
        self.next_version += 1
        data = dict(manifest.get("data", {}))
        for k, v in manifest.get("stringData", {}).items():
            data[k] = base64.b64encode(v.encode()).decode()
        annotations = dict(meta.get("annotations", {}))
        if annotate:
            annotations[LAST_APPLIED] = json.dumps(manifest)
        meta["annotations"] = annotations
        self.secrets[(meta["namespace"], meta["name"])] = {
            "metadata": meta, "data": data, "type": manifest.get("type", "Opaque"),
            "immutable": manifest.get("immutable", False)}

    def secret_value(self, namespace, name, key):
        return base64.b64decode(self.secrets[(namespace, name)]["data"][key]).decode()

    def verbs(self):
        return [c["argv"][1] for c in self.calls]


class FakeAxiom:
    """Axiom admin, token and identity-control APIs as the publisher uses them. ``supports_supplied`` False models an
    older server that ignores ``clientSecret`` and mints its own. ``faults`` maps an operation to a callable that may
    raise (simulating a crash or lost response) after optionally letting the operation take effect."""

    def __init__(self, supports_supplied=True):
        self.supports_supplied = supports_supplied
        self.clients: dict[str, dict] = {}
        self.secrets: dict[str, str] = {}
        self.posts = 0
        self.post_bodies: list[dict] = []
        self.issued: dict[str, str] = {}
        self.token_calls: list[tuple[str, str]] = []
        self.revoked = 0
        self.requests: dict[str, dict] = {}
        self.faults: dict = {}
        self.token_status_override = None

    def fault(self, name, when):
        fn = self.faults.get((name, when))
        if fn:
            fn(self)

    def request(self, path, *, method="GET", body=None, **kw):
        if method == "GET" and path.endswith("/applications"):
            return [{"id": "app-1", "applicationKey": "app-a"}]
        if method == "GET" and path.endswith("/clients"):
            return [dict(c) for c in self.clients.values()]
        if method == "POST" and path.endswith("/clients"):
            self.fault("post", "before")
            self.posts += 1
            self.post_bodies.append(dict(body))
            if body["clientId"] in self.clients:
                raise RuntimeError(f"POST {path} returned HTTP 409: {{\"message\":\"Client id already exists\"}}")
            client = {"id": f"cid-{body['clientId']}", "clientId": body["clientId"], "clientType": body["clientType"],
                      "scopes": body["scopes"], "status": "ACTIVE", "revision": 1}
            supplied = body.get("clientSecret") if self.supports_supplied else None
            secret = supplied or ("minted-" + os.urandom(16).hex())
            self.clients[body["clientId"]] = client
            self.secrets[body["clientId"]] = secret
            self.issued[body["clientId"]] = secret
            self.fault("post", "after")
            return {"client": dict(client), "serviceSecret": None if supplied else secret}
        if "/identity-control-requests" in path:
            return self.identity_control(path, method, body)
        raise AssertionError(f"unexpected API call {method} {path}")

    def identity_control(self, path, method, body):
        tail = path.split("/identity-control-requests", 1)[1]
        if method == "GET" and tail.startswith("?"):
            return {"content": [dict(r) for r in self.requests.values()]}
        if method == "POST" and tail == "":
            self.fault("propose", "before")
            rid = f"req-{len(self.requests) + 1}"
            self.requests[rid] = {"id": rid, "status": "PENDING", "revision": 1, "targetId": body["targetId"],
                                  "action": body["action"], "expectedTargetRevision": body["expectedTargetRevision"],
                                  "payloadHash": configure.rotation_payload_hash(body["payload"]["recoveryId"]),
                                  "_payload": body["payload"]}
            self.fault("propose", "after")
            return {k: v for k, v in self.requests[rid].items() if not k.startswith("_")}
        rid = tail.strip("/").split("/")[0]
        request = self.requests[rid]
        if method == "GET":
            return {k: v for k, v in request.items() if not k.startswith("_")}
        if tail.endswith("/apply"):
            if request["status"] == "APPLIED":
                return {"request": request, "oneTimeSecret": None}
            assert request["status"] == "APPROVED" and body["expectedRevision"] == request["revision"]
            client_id = next(c for c, v in self.clients.items() if v["id"] == request["targetId"])
            supplied = request["_payload"].get("clientSecret") if self.supports_supplied else None
            self.secrets[client_id] = supplied or ("minted-" + os.urandom(16).hex())
            request["status"], request["revision"] = "APPLIED", request["revision"] + 1
            return {"request": request, "oneTimeSecret": None if supplied else self.secrets[client_id]}
        raise AssertionError(path)

    def approve(self, rid):
        self.requests[rid]["status"], self.requests[rid]["revision"] = "APPROVED", 2

    def client_credentials(self, client_id, client_secret, scope):
        self.token_calls.append((client_id, client_secret))
        if self.token_status_override is not None:
            return self.token_status_override, {"error": "server_error"}
        if self.secrets.get(client_id) == client_secret and self.clients[client_id]["status"] == "ACTIVE":
            self.revoked += 1  # the real client revokes the proof token
            return 200, {"token_type": "Bearer"}
        return 401, {"error": "invalid_client"}


SPEC = {"clientId": "agent-a", "applicationKey": "app-a", "scopes": ["quickstart:invoke"],
        "kubernetesSecret": {"namespace": "agents", "name": "agent-a-oauth-client"}}
LOCAL_SPEC = {"clientId": "agent-local", "applicationKey": "app-a", "scopes": ["quickstart:invoke"]}


class PublisherFixture:
    """Shared temporary state, fake kubectl and fake Axiom for the configure_axiom.py test classes."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="axiom-cfg-test-"))
        self.secret_file = self.tmp / ".local" / "configured-agent-clients.json"
        self.pending_file = self.secret_file.with_name(configure.PENDING_FILE_NAME)
        self.kubectl = FakeKubectl(subprocess.run)
        self.saved_run = configure.subprocess.run
        configure.subprocess.run = self.kubectl
        self.api = FakeAxiom()

    def tearDown(self):
        import shutil
        configure.subprocess.run = self.saved_run
        shutil.rmtree(self.tmp, ignore_errors=True)

    def publisher(self):
        bundle = {"tenant": {"id": "meridian"}, "agent_workloads": [SPEC], "trusted_brokers": []}
        return configure.Publisher(self.api, bundle, self.secret_file)

    def publish(self, spec=SPEC):
        return self.publisher().ensure_client({"id": "app-1"}, spec, "CONFIDENTIAL_SERVICE")

    def pending(self):
        return json.loads(self.pending_file.read_text()) if self.pending_file.exists() else {}

    def assert_no_secret_leak(self):
        for call in self.kubectl.calls:
            for secret in self.api.issued.values():
                self.assertNotIn(secret, " ".join(call["argv"]), "credential in argv")
        for obj in self.kubectl.secrets.values():
            self.assertNotIn(LAST_APPLIED, obj["metadata"]["annotations"])



class ConfigureAxiomDeliveryTest(PublisherFixture, unittest.TestCase):
    # -- functional -------------------------------------------------------------------------------------------------
    def test_new_client_secret_is_created_without_apply_or_annotation(self):
        self.publish()
        self.assertEqual(self.api.posts, 1)
        self.assertNotIn("apply", self.kubectl.verbs())
        creates = [c["argv"] for c in self.kubectl.calls if c["argv"][1] == "create"]
        self.assertEqual(creates, [["kubectl", "create", "-f", "-", "--dry-run=server", "-o", "name"],
                                   ["kubectl", "create", "-f", "-"]])
        for argv in creates:
            self.assertNotIn("--save-config", argv)
        self.assertEqual(self.kubectl.secret_value("agents", "agent-a-oauth-client", "client_secret"),
                         self.api.issued["agent-a"])
        self.assertEqual(self.kubectl.secrets[("agents", "agent-a-oauth-client")]["metadata"]["annotations"], {})
        dry = [c for c in self.kubectl.calls if "--dry-run=server" in c["argv"]][0]
        self.assertNotIn(self.api.issued["agent-a"], dry["stdin"], "real secret never sent in the dry run")
        self.assertFalse(self.pending_file.exists(), "escrow is removed after verified delivery")
        self.assertFalse(self.secret_file.exists(), "Kubernetes-bound secret never lands in the local output file")
        self.assert_no_secret_leak()

    def test_escrow_is_durable_and_private_before_the_secret_is_created(self):
        seen = {}

        def on_create(kubectl, key):
            seen["pending"] = json.loads(self.pending_file.read_text())
            seen["mode"] = stat.S_IMODE(self.pending_file.stat().st_mode)
            seen["dir_mode"] = stat.S_IMODE(self.pending_file.parent.stat().st_mode)

        self.kubectl.on_create = on_create
        self.publish()
        entry = seen["pending"]["meridian"]["agent-a"]
        self.assertEqual(entry["client_secret"], self.api.issued["agent-a"])
        self.assertEqual((entry["namespace"], entry["name"]), ("agents", "agent-a-oauth-client"))
        self.assertEqual(seen["mode"], 0o600)
        self.assertEqual(seen["dir_mode"], 0o700)

    def test_replay_of_an_existing_client_is_read_only(self):
        self.publish()
        calls = len(self.kubectl.calls)
        self.publish()
        self.assertEqual(self.api.posts, 1)
        self.assertEqual([c["argv"][1] for c in self.kubectl.calls[calls:]], ["get"])

    def test_access_check_requires_get_and_create_only(self):
        self.publisher().ensure_kubernetes_secret_access()
        verbs = [c["argv"][3] for c in self.kubectl.calls]
        self.assertEqual(verbs, ["get", "create"])

    # -- failure and retry ------------------------------------------------------------------------------------------
    def test_failed_secret_creation_is_retried_from_escrow_without_reminting(self):
        self.kubectl.faults[("create", "real")] = lambda k, argv, m: k.done(argv, 1, err="connection refused")
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish()
        self.assertIn("next run retries delivery", str(failure.exception))
        self.assertNotIn(self.api.issued["agent-a"], str(failure.exception))
        self.assertEqual(self.api.posts, 1)
        self.assertNotIn(("agents", "agent-a-oauth-client"), self.kubectl.secrets)
        self.assertEqual(self.pending()["meridian"]["agent-a"]["client_secret"], self.api.issued["agent-a"])
        self.assertEqual(stat.S_IMODE(self.pending_file.stat().st_mode), 0o600)

        # A second failure keeps the escrow too.
        with self.assertRaises(configure.ConfigurationError):
            self.publish()
        self.assertEqual(self.api.posts, 1)
        self.assertIn("agent-a", self.pending()["meridian"])

        # Recovery: the next run delivers the originally issued credential; nothing is minted again.
        del self.kubectl.faults[("create", "real")]
        self.publish()
        self.assertEqual(self.api.posts, 1)
        self.assertEqual(self.kubectl.secret_value("agents", "agent-a-oauth-client", "client_secret"),
                         self.api.issued["agent-a"])
        self.assertFalse(self.pending_file.exists())
        self.assert_no_secret_leak()

    def test_ambiguous_failure_after_the_secret_was_created_is_reconciled(self):
        def created_then_failed(k, argv, manifest):
            k.store(manifest)
            return k.done(argv, 1, err="timeout awaiting response")

        self.kubectl.faults[("create", "real")] = created_then_failed
        with self.assertRaises(configure.ConfigurationError):
            self.publish()
        self.assertIn("agent-a", self.pending()["meridian"])
        del self.kubectl.faults[("create", "real")]
        before = sum(1 for c in self.kubectl.calls if c["argv"][1] == "create")
        self.publish()
        after = sum(1 for c in self.kubectl.calls if c["argv"][1] == "create")
        self.assertEqual(after, before, "an existing matching Secret is adopted, not re-created")
        self.assertFalse(self.pending_file.exists())

    def test_interrupted_run_after_minting_is_recovered(self):
        def interrupted(k, argv, manifest):
            raise KeyboardInterrupt

        self.kubectl.faults[("create", "real")] = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.publish()
        self.assertIn("agent-a", self.pending()["meridian"])
        del self.kubectl.faults[("create", "real")]
        self.publish()
        self.assertEqual(self.api.posts, 1)
        self.assertEqual(self.kubectl.secret_value("agents", "agent-a-oauth-client", "client_secret"),
                         self.api.issued["agent-a"])

    def test_existing_secret_blocks_minting(self):
        self.kubectl.store({"metadata": {"namespace": "agents", "name": "agent-a-oauth-client"},
                            "stringData": {"client_id": "agent-a", "client_secret": "stale"}})
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish()
        self.assertIn("already exists", str(failure.exception))
        self.assertIn("no credential was minted", str(failure.exception))
        self.assertEqual(self.api.posts, 0)
        self.assertEqual(self.kubectl.secret_value("agents", "agent-a-oauth-client", "client_secret"), "stale")
        self.assertFalse(self.pending_file.exists())

    def test_server_side_rejection_blocks_minting(self):
        self.kubectl.faults[("create", "dry")] = lambda k, argv, m: k.done(argv, 1, err="forbidden")
        with self.assertRaises(configure.ConfigurationError):
            self.publish()
        self.assertEqual(self.api.posts, 0)

    def test_unwritable_escrow_directory_blocks_minting(self):
        self.secret_file.parent.mkdir(mode=0o500, parents=True)
        try:
            with self.assertRaises(configure.ConfigurationError):
                self.publish()
        finally:
            self.secret_file.parent.chmod(0o700)
        self.assertEqual(self.api.posts, 0)

    # -- escrow directory safety (checked before any confidential secret is minted) ----------------------------------
    def assert_refused_before_minting(self, spec=SPEC, text=""):
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish(spec)
        self.assertIn(text, str(failure.exception))
        self.assertEqual(self.api.posts, 0, "no credential minted")
        self.assertEqual([c for c in self.kubectl.calls if c["argv"][1] == "create"], [], "no Secret touched")
        return failure.exception

    def test_existing_0755_directory_is_refused_and_left_unchanged(self):
        directory = self.secret_file.parent
        directory.mkdir()
        directory.chmod(0o755)
        for spec in (SPEC, LOCAL_SPEC):
            self.assert_refused_before_minting(spec, "must have mode 0700 but has 0755")
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755, "never silently repaired")
        self.assertEqual(list(directory.iterdir()), [])

    def test_symlinked_directory_is_refused_even_if_its_target_is_private(self):
        target = self.tmp / "elsewhere"
        target.mkdir(mode=0o700)
        self.secret_file.parent.symlink_to(target, target_is_directory=True)
        for spec in (SPEC, LOCAL_SPEC):
            self.assert_refused_before_minting(spec, "symbolic link")
        self.assertTrue(self.secret_file.parent.is_symlink())
        self.assertEqual(list(target.iterdir()), [], "nothing written through the link")

    def test_directory_owned_by_another_user_is_refused(self):
        self.secret_file.parent.mkdir(mode=0o700)
        real = configure.os.geteuid
        configure.os.geteuid = lambda: real() + 1  # offline stand-in for a foreign owner
        try:
            self.assert_refused_before_minting(SPEC, "not owned by the current user")
        finally:
            configure.os.geteuid = real

    def test_regular_file_in_place_of_the_directory_is_refused(self):
        self.secret_file.parent.write_text("not a directory")
        self.assert_refused_before_minting(SPEC, "not a directory")

    def test_safe_existing_directory_is_used_as_is(self):
        directory = self.secret_file.parent
        directory.mkdir(mode=0o700)
        keep = directory / "unrelated.txt"
        keep.write_text("operator file")
        before = os.lstat(directory)
        self.publish()
        self.publish(LOCAL_SPEC)
        after = os.lstat(directory)
        self.assertEqual((after.st_ino, stat.S_IMODE(after.st_mode)), (before.st_ino, 0o700))
        self.assertEqual(keep.read_text(), "operator file")
        self.assertEqual(self.api.posts, 2)
        self.assertEqual(sorted(p.name for p in directory.iterdir()),
                         ["configured-agent-clients.json", "unrelated.txt"])

    def test_missing_directory_is_created_private(self):
        self.publish()
        self.assertEqual(stat.S_IMODE(os.lstat(self.secret_file.parent).st_mode), 0o700)

    def test_directory_made_unsafe_after_a_failed_delivery_keeps_the_escrow(self):
        self.kubectl.faults[("create", "real")] = lambda k, argv, m: k.done(argv, 1, err="refused")
        with self.assertRaises(configure.ConfigurationError):
            self.publish()
        del self.kubectl.faults[("create", "real")]
        self.secret_file.parent.chmod(0o755)
        # The Secret is created and verified, but the escrow cannot be rewritten through an unsafe directory,
        # so the run fails closed and the escrow entry is not removed.
        with self.assertRaises(configure.ConfigurationError):
            self.publish()
        self.secret_file.parent.chmod(0o700)
        self.assertIn("agent-a", self.pending()["meridian"])
        self.publish()  # once fixed deliberately, the next run adopts the matching Secret and clears the escrow
        self.assertFalse(self.pending_file.exists())
        self.assertEqual(self.api.posts, 1)

    def test_a_different_credential_in_the_secret_keeps_the_escrow(self):
        def someone_else_wrote_it(k, argv, manifest):
            k.store({"metadata": manifest["metadata"],
                     "stringData": {"client_id": "agent-a", "client_secret": "not-ours"}})
            return k.done(argv, 1, err="AlreadyExists")

        self.kubectl.faults[("create", "real")] = someone_else_wrote_it
        with self.assertRaises(configure.ConfigurationError):
            self.publish()
        del self.kubectl.faults[("create", "real")]
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish()
        self.assertIn("different credential", str(failure.exception))
        self.assertEqual(self.pending()["meridian"]["agent-a"]["client_secret"], self.api.issued["agent-a"])
        self.assertEqual(self.kubectl.secret_value("agents", "agent-a-oauth-client", "client_secret"), "not-ours")

    def test_changed_destination_keeps_the_escrow(self):
        self.kubectl.faults[("create", "real")] = lambda k, argv, m: k.done(argv, 1, err="refused")
        with self.assertRaises(configure.ConfigurationError):
            self.publish()
        del self.kubectl.faults[("create", "real")]
        moved = {**SPEC, "kubernetesSecret": {"namespace": "agents", "name": "renamed"}}
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish(moved)
        self.assertIn("stays in", str(failure.exception))
        self.assertIn("agent-a", self.pending()["meridian"])
        self.assertEqual(self.kubectl.secrets, {})

    def test_pending_credential_without_a_client_resumes_with_the_escrowed_secret(self):
        escrowed = configure.new_client_secret()
        self.pending_file.parent.mkdir(mode=0o700, parents=True)
        configure.write_private_json(self.pending_file, {"meridian": {"agent-a": {
            "namespace": "agents", "name": "agent-a-oauth-client", "client_secret": escrowed}}})
        self.publish()
        self.assertEqual(self.api.posts, 1)
        self.assertEqual(self.api.post_bodies[0]["clientSecret"], escrowed, "the escrowed value, not a new one")
        self.assertEqual(self.kubectl.secret_value("agents", "agent-a-oauth-client", "client_secret"), escrowed)
        self.assertFalse(self.pending_file.exists())

    def test_local_only_client_secret_is_persisted_immediately(self):
        self.publish(LOCAL_SPEC)
        state = json.loads(self.secret_file.read_text())
        self.assertEqual(state["meridian"]["agent-local"], self.api.issued["agent-local"])
        self.assertEqual(stat.S_IMODE(self.secret_file.stat().st_mode), 0o600)
        self.assertNotIn("create", self.kubectl.verbs())

    def test_private_writer_never_exposes_a_readable_temporary(self):
        opened = []
        real_open = os.open

        def spy(path, flags, mode=0o777, *a, **k):
            if str(path).endswith(".tmp"):
                opened.append((flags, mode))
            return real_open(path, flags, mode, *a, **k)

        configure.os.open = spy
        try:
            configure.write_private_json(self.tmp / "d" / "s.json", {"k": "v"})
        finally:
            configure.os.open = real_open
        self.assertEqual(len(opened), 1)
        flags, mode = opened[0]
        self.assertTrue(flags & os.O_EXCL and flags & os.O_CREAT)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE((self.tmp / "d").stat().st_mode), 0o700)
        self.assertEqual([p.name for p in (self.tmp / "d").iterdir()], ["s.json"])


class OperatorSuppliedSecretFlowTest(PublisherFixture, unittest.TestCase):
    """Package A: the operator generates and escrows the secret before any API call; every delivery is preceded by
    a possession proof; anything unprovable or minted by Axiom itself fails closed with the escrow kept."""

    def secret_in_k8s(self):
        return self.kubectl.secret_value("agents", "agent-a-oauth-client", "client_secret")

    def publisher_with(self, *specs):
        bundle = {"tenant": {"id": "meridian"}, "agent_workloads": list(specs), "trusted_brokers": []}
        return configure.Publisher(self.api, bundle, self.secret_file)

    def test_escrow_precedes_the_create_call_and_the_call_carries_that_value(self):
        seen = {}

        def at_post(api):
            seen["escrow"] = json.loads(self.pending_file.read_text())["meridian"]["agent-a"]["client_secret"]
            seen["mode"] = stat.S_IMODE(self.pending_file.stat().st_mode)

        self.api.faults[("post", "before")] = at_post
        self.publish()
        sent = self.api.post_bodies[0]["clientSecret"]
        self.assertEqual(seen["escrow"], sent)
        self.assertEqual(seen["mode"], 0o600)
        self.assertRegex(sent, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(self.api.token_calls, [("agent-a", sent)], "possession proved before delivery")
        self.assertEqual(self.api.revoked, 1, "proof token revoked")
        self.assertEqual(self.secret_in_k8s(), sent)
        self.assertFalse(self.pending_file.exists())

    def test_crash_before_the_create_call_retries_with_the_same_secret(self):
        def crash(api):
            api.faults.pop(("post", "before"))
            raise KeyboardInterrupt
        self.api.faults[("post", "before")] = crash
        with self.assertRaises(KeyboardInterrupt):
            self.publish()
        escrowed = self.pending()["meridian"]["agent-a"]["client_secret"]
        self.assertEqual(self.api.clients, {})
        self.publish()
        self.assertEqual([b["clientSecret"] for b in self.api.post_bodies], [escrowed])
        self.assertEqual(self.secret_in_k8s(), escrowed)

    def test_lost_create_response_is_recovered_by_possession_proof(self):
        def lost(api):
            api.faults.pop(("post", "after"))
            raise RuntimeError("cannot reach Axiom at http://axiom: timed out")
        self.api.faults[("post", "after")] = lost
        with self.assertRaises(RuntimeError):
            self.publish()
        escrowed = self.pending()["meridian"]["agent-a"]["client_secret"]
        self.assertIn("agent-a", self.api.clients, "the client was created server-side")
        self.publish()
        self.assertEqual(self.api.posts, 1, "no second create")
        self.assertEqual(self.secret_in_k8s(), escrowed)
        self.assertFalse(self.pending_file.exists())

    def test_create_conflict_from_a_racing_attempt_is_proved_not_overwritten(self):
        def racing(api):
            api.faults.pop(("post", "before"))
            escrowed = json.loads(self.pending_file.read_text())["meridian"]["agent-a"]["client_secret"]
            api.clients["agent-a"] = {"id": "cid-agent-a", "clientId": "agent-a", "clientType": "CONFIDENTIAL_SERVICE",
                                      "scopes": SPEC["scopes"], "status": "ACTIVE", "revision": 1}
            api.secrets["agent-a"] = escrowed
        self.api.faults[("post", "before")] = racing
        self.publish()
        self.assertEqual(self.secret_in_k8s(), self.api.secrets["agent-a"])
        self.assertFalse(self.pending_file.exists())

    def test_escrowed_secret_that_does_not_authenticate_fails_closed(self):
        self.pending_file.parent.mkdir(mode=0o700, parents=True)
        escrowed = configure.new_client_secret()
        configure.write_private_json(self.pending_file, {"meridian": {"agent-a": {
            "namespace": "agents", "name": "agent-a-oauth-client", "client_secret": escrowed, "phase": "create"}}})
        self.api.clients["agent-a"] = {"id": "cid-agent-a", "clientId": "agent-a", "clientType": "CONFIDENTIAL_SERVICE",
                                       "scopes": SPEC["scopes"], "status": "ACTIVE", "revision": 1}
        self.api.secrets["agent-a"] = "someone-else-" + os.urandom(8).hex()
        before = self.pending_file.read_bytes()
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish()
        self.assertIn("does not authenticate", str(failure.exception))
        self.assertIn("--rotate-client", str(failure.exception))
        self.assertNotIn(escrowed, str(failure.exception))
        self.assertEqual(self.pending_file.read_bytes(), before, "escrow unchanged")
        self.assertEqual(self.kubectl.secrets, {}, "nothing delivered")
        self.assertEqual(self.api.posts, 0)

    def test_indeterminate_possession_keeps_the_escrow(self):
        self.api.token_status_override = 503
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish()
        self.assertIn("could not be proved", str(failure.exception))
        self.assertIn("agent-a", self.pending()["meridian"])
        self.assertEqual(self.kubectl.secrets, {})
        self.api.token_status_override = None
        self.publish()
        self.assertEqual(self.secret_in_k8s(), self.api.secrets["agent-a"])

    def test_disabled_client_is_refused_not_delivered(self):
        def crash(api):
            api.faults.pop(("post", "after"))
            api.clients["agent-a"]["status"] = "DISABLED"
            raise RuntimeError("cannot reach Axiom")
        self.api.faults[("post", "after")] = crash
        with self.assertRaises(RuntimeError):
            self.publish()
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish()
        self.assertIn("DISABLED", str(failure.exception))
        self.assertEqual(self.kubectl.secrets, {})

    def test_older_server_that_mints_its_own_secret_is_rejected_and_quarantined(self):
        self.api.supports_supplied = False
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publish()
        minted = self.api.secrets["agent-a"]
        entry = self.pending()["meridian"]["agent-a"]
        self.assertNotEqual(entry["client_secret"], minted)
        self.assertEqual(entry["server_minted_secret"], minted)
        self.assertEqual(entry["state"], "quarantined-server-minted-secret")
        self.assertEqual(self.kubectl.secrets, {}, "nothing delivered")
        self.assertEqual(self.api.token_calls, [])
        self.assertNotIn(minted, str(failure.exception))
        self.assertNotIn(entry["client_secret"], str(failure.exception))
        with self.assertRaises(configure.ConfigurationError) as again:
            self.publish()
        self.assertIn("quarantined", str(again.exception))
        self.assertEqual(self.kubectl.secrets, {})

    def test_local_destination_is_escrowed_first_and_written_only_after_proof(self):
        seen = {}
        self.api.faults[("post", "before")] = lambda api: seen.setdefault(
            "pending", json.loads(self.pending_file.read_text())["meridian"]["agent-local"])
        self.publish(LOCAL_SPEC)
        self.assertTrue(seen["pending"]["local"])
        state = json.loads(self.secret_file.read_text())
        self.assertEqual(state["meridian"]["agent-local"], self.api.post_bodies[0]["clientSecret"])
        self.assertFalse(self.pending_file.exists())

    # -- approval-gated rotation --------------------------------------------------------------------------------
    def published_client(self):
        self.publish()
        return self.publisher_with(SPEC), self.secret_in_k8s()

    def test_rotation_is_escrowed_proposed_approved_by_another_admin_then_proved_and_delivered(self):
        publisher, original = self.published_client()
        seen = {}
        self.api.faults[("propose", "before")] = lambda api: seen.setdefault(
            "escrow", json.loads(self.pending_file.read_text())["meridian"]["agent-a"])
        proposed = publisher.propose_rotation("agent-a")
        replacement = seen["escrow"]["client_secret"]
        self.assertEqual(seen["escrow"]["phase"], "rotation")
        self.assertEqual(len(seen["escrow"]["recovery_id"]), 43)
        self.assertNotEqual(seen["escrow"]["recovery_id"], replacement)
        self.assertEqual(proposed["status"], "PENDING")
        self.assertNotIn(replacement, json.dumps(proposed))

        waiting = self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertEqual(waiting["status"], "PENDING")
        self.assertEqual(self.secret_in_k8s(), original, "nothing changes before approval")

        self.api.approve(proposed["requestId"])
        done = self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertEqual(done["status"], "APPLIED")
        self.assertEqual(self.api.secrets["agent-a"], replacement)
        self.assertEqual(self.secret_in_k8s(), replacement)
        self.assertIn(["kubectl", "replace", "-f", "-"], [c["argv"] for c in self.kubectl.calls])
        self.assertEqual(self.kubectl.secrets[("agents", "agent-a-oauth-client")]["metadata"]["annotations"], {})
        self.assertFalse(self.pending_file.exists())
        self.assert_no_secret_leak()

    def test_rotation_replace_preserves_unrelated_fields_and_removes_old_apply_annotation(self):
        publisher, _ = self.published_client()
        key = ("agents", "agent-a-oauth-client")
        current = self.kubectl.secrets[key]
        current["metadata"]["labels"]["owner.example/team"] = "agents"
        current["metadata"]["annotations"]["owner.example/note"] = "keep"
        current["metadata"]["annotations"][LAST_APPLIED] = "old-sensitive-config"
        current["data"]["extra"] = base64.b64encode(b"keep-me").decode()
        old_version = current["metadata"]["resourceVersion"]
        proposed = publisher.propose_rotation("agent-a")
        self.api.approve(proposed["requestId"])

        self.publisher_with(SPEC).complete_rotation("agent-a")

        replaced = self.kubectl.secrets[key]
        self.assertNotEqual(replaced["metadata"]["resourceVersion"], old_version)
        self.assertEqual(replaced["metadata"]["labels"]["owner.example/team"], "agents")
        self.assertEqual(replaced["metadata"]["annotations"], {"owner.example/note": "keep"})
        self.assertEqual(base64.b64decode(replaced["data"]["extra"]), b"keep-me")

    def test_rotation_replace_conflict_keeps_escrow_for_retry(self):
        publisher, original = self.published_client()
        proposed = publisher.propose_rotation("agent-a")
        self.api.approve(proposed["requestId"])
        key = ("agents", "agent-a-oauth-client")

        def concurrent_update(fake, argv, manifest):
            if argv[1] == "replace":
                fake.secrets[key]["metadata"]["resourceVersion"] = "concurrent-change"
            return None

        self.kubectl.faults[("create", "real")] = concurrent_update
        with self.assertRaises(configure.ConfigurationError):
            self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertEqual(self.secret_in_k8s(), original)
        self.assertTrue(self.pending_file.exists())
        del self.kubectl.faults[("create", "real")]
        self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertFalse(self.pending_file.exists())

    def test_rotation_refuses_a_secret_owned_by_someone_else(self):
        publisher, original = self.published_client()
        proposed = publisher.propose_rotation("agent-a")
        self.api.approve(proposed["requestId"])
        key = ("agents", "agent-a-oauth-client")
        self.kubectl.secrets[key]["metadata"]["labels"]["app.kubernetes.io/managed-by"] = "someone-else"
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertIn("ownership differs", str(failure.exception))
        self.assertEqual(self.secret_in_k8s(), original)
        self.assertTrue(self.pending_file.exists())

    def test_lost_propose_response_does_not_create_a_second_request(self):
        publisher, _ = self.published_client()

        def lost(api):
            api.faults.pop(("propose", "after"))
            raise RuntimeError("cannot reach Axiom")
        self.api.faults[("propose", "after")] = lost
        with self.assertRaises(RuntimeError):
            publisher.propose_rotation("agent-a")
        result = self.publisher_with(SPEC).propose_rotation("agent-a")
        self.assertEqual(len(self.api.requests), 1, "found by payload hash, not proposed again")
        self.assertEqual(result["requestId"], "req-1")

    def test_rejected_rotation_discards_the_never_applied_escrow(self):
        publisher, original = self.published_client()
        proposed = publisher.propose_rotation("agent-a")
        self.api.requests[proposed["requestId"]]["status"] = "REJECTED"
        result = self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertEqual(result["escrow"], "discarded")
        self.assertFalse(self.pending_file.exists())
        self.assertEqual(self.secret_in_k8s(), original)

    def test_failed_rotation_delivery_keeps_the_escrow_and_retries(self):
        publisher, _ = self.published_client()
        proposed = publisher.propose_rotation("agent-a")
        self.api.approve(proposed["requestId"])
        self.kubectl.faults[("create", "real")] = lambda k, argv, m: k.done(argv, 1, err="refused") \
            if argv[1] == "replace" else None
        with self.assertRaises(configure.ConfigurationError):
            self.publisher_with(SPEC).complete_rotation("agent-a")
        replacement = self.pending()["meridian"]["agent-a"]["client_secret"]
        self.assertEqual(self.api.secrets["agent-a"], replacement, "applied server-side")
        del self.kubectl.faults[("create", "real")]
        self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertEqual(self.secret_in_k8s(), replacement)
        self.assertFalse(self.pending_file.exists())

    def test_rotation_whose_applied_secret_does_not_authenticate_fails_closed(self):
        publisher, original = self.published_client()
        proposed = publisher.propose_rotation("agent-a")
        self.api.approve(proposed["requestId"])
        self.api.supports_supplied = False  # server applies a generated secret instead
        with self.assertRaises(configure.ConfigurationError) as failure:
            self.publisher_with(SPEC).complete_rotation("agent-a")
        self.assertIn("quarantined", str(failure.exception))
        self.assertEqual(self.secret_in_k8s(), original, "nothing delivered")
        self.assertEqual(self.pending()["meridian"]["agent-a"]["state"], "quarantined-server-minted-secret")

    def test_rotation_fingerprint_does_not_hash_the_secret(self):
        recovery_id = "R" * 43
        self.assertEqual(configure.rotation_payload_hash(recovery_id),
                         __import__("hashlib").sha256(("client-secret-rotation:" + recovery_id).encode()).hexdigest())
        self.assertNotEqual(configure.rotation_payload_hash(recovery_id),
                            __import__("hashlib").sha256(b'{"clientSecret":"abc"}').hexdigest())


class SigningSecretTest(unittest.TestCase):
    def setUp(self):
        self.kubectl = FakeKubectl(subprocess.run)
        self.saved = (signing.subprocess.run, sys.argv)
        signing.subprocess.run = self.kubectl
        self.out = pathlib.Path(tempfile.mkdtemp(prefix="axiom-signing-test-"))

    def tearDown(self):
        import shutil
        signing.subprocess.run, sys.argv = self.saved
        shutil.rmtree(self.out, ignore_errors=True)

    def run_script(self, *args):
        sys.argv = ["create-signing-secret.py", "--namespace", "axiom", *args]
        signing.main()

    def test_apply_mode_creates_an_immutable_secret_without_annotation(self):
        self.run_script("--apply", "--output-dir", str(self.out))
        self.assertNotIn("apply", self.kubectl.verbs())
        create = [c for c in self.kubectl.calls if c["argv"][1] == "create"]
        self.assertEqual([c["argv"] for c in create], [["kubectl", "create", "-f", "-"]])
        obj = self.kubectl.secrets[("axiom", "axiom-signing-key")]
        self.assertTrue(obj["immutable"])
        self.assertEqual(obj["metadata"]["annotations"], {})
        private = json.loads(base64.b64decode(obj["data"]["signing-key.json"]))
        self.assertIn("d", private)
        for call in self.kubectl.calls:
            self.assertNotIn(private["d"], " ".join(call["argv"]))

    def test_existing_signing_secret_is_never_replaced(self):
        self.kubectl.store({"metadata": {"namespace": "axiom", "name": "axiom-signing-key"},
                            "data": {"signing-key.json": "b3JpZ2luYWw="}, "immutable": True})
        with self.assertRaises(SystemExit) as refused:
            self.run_script("--apply")
        self.assertIn("refusing to replace", str(refused.exception))
        self.assertNotIn("create", self.kubectl.verbs())
        self.assertEqual(self.kubectl.secrets[("axiom", "axiom-signing-key")]["data"]["signing-key.json"],
                         "b3JpZ2luYWw=")

    def test_create_race_fails_without_replacing_the_existing_key(self):
        def appeared(k, argv, manifest):
            k.store({"metadata": manifest["metadata"], "data": {"signing-key.json": "cmFjZQ=="}})
            return None  # fall through: create now sees AlreadyExists

        self.kubectl.faults[("create", "real")] = appeared
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_script("--apply")
        self.assertEqual(self.kubectl.secrets[("axiom", "axiom-signing-key")]["data"]["signing-key.json"],
                         "cmFjZQ==")


if __name__ == "__main__":
    unittest.main()
