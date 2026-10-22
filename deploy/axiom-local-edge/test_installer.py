"""Offline safety tests for the disposable local Axiom installer."""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load_module("axiom_local_installer", HERE / "installer.py")
private = load_module("axiom_private_helper", HERE / "prepare-private.py")


class LocalInstallerTest(unittest.TestCase):
    def test_build_context_must_exclude_deployment_private_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / ".dockerignore").write_text("docs/\n")
            def fake_run(*args):
                return str(root) if "--show-toplevel" in args else installer.BRANCH
            with patch.object(installer, "ROOT", root), patch.object(installer, "run", side_effect=fake_run):
                with self.assertRaisesRegex(installer.InstallError, "plaintext private files"):
                    installer.check_source()
                (root / ".dockerignore").write_text("docs/\ndeploy/\n")
                installer.check_source()

    def test_source_tag_changes_with_server_input_but_not_unrelated_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in (
                ("server/Dockerfile", "FROM example@sha256:abc"),
                ("server/pom.xml", "<project/>"),
                ("server/src/Example.java", "class Example {}"),
                ("platform-policy/policy.yaml", "allow: false"),
                ("platform-contract/contract.json", "{}"),
                (".dockerignore", "target"),
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            with patch.object(installer, "ROOT", root):
                original = installer.image_tag("server")
                self.assertEqual(original, installer.image_tag("server"))
                (root / "unrelated.txt").write_text("not in Docker build inputs")
                self.assertEqual(original, installer.image_tag("server"))
                (root / "server/src/Example.java").write_text("class Changed {}")
                self.assertNotEqual(original, installer.image_tag("server"))

    def test_existing_release_must_match_expected_chart(self) -> None:
        namespaces = {name: {"metadata": {"labels": {
            f"pod-security.kubernetes.io/{mode}": "restricted"
            for mode in ("enforce", "audit", "warn")}}}
            for name in ("axiom", "gateway-demo")}
        namespaces["envoy-gateway-system"] = {"metadata": {"labels": {}}}

        def fake_release(namespace, name):
            return {"status": "deployed", "chart": "unexpected-9.9"} if name == "axiom" else {}

        with patch.object(installer, "kube_json", side_effect=lambda *args: namespaces.get(args[-1], {})), \
             patch.object(installer, "release", side_effect=fake_release), \
             patch.object(installer, "run", return_value="[]"):
            with self.assertRaisesRegex(installer.InstallError, "not the expected deployed chart"):
                installer.check_namespace_safety()

    def test_network_canary_requires_denial_and_always_cleans_up(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_kube(*args):
            calls.append(args)
            if "logs" in args:
                return "Redis Service DNS resolved.\nUNEXPECTED_REDIS_REACHABILITY"
            return ""

        with patch.object(installer, "kube_json", return_value={}), \
             patch.object(installer, "kube", side_effect=fake_kube):
            with self.assertRaisesRegex(installer.InstallError, "did not prove"):
                installer.network_canary()
        self.assertTrue(any("delete" in args for args in calls))


class PrivateSecretTest(unittest.TestCase):
    def test_matching_secret_is_retained_and_mismatch_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "password"
            credential.write_text("test-only-password")
            encoded = base64.b64encode(credential.read_bytes()).decode("ascii")
            existing = {"type": "Opaque", "data": {"password": encoded}}
            self.assertTrue(private.secret_matches(existing, {"password": credential}, "Opaque"))
            self.assertFalse(private.secret_matches(existing, {"password": credential}, "Opaque", True))
            with patch.object(private.subprocess, "run") as get_secret, \
                 patch.object(private, "create_secret") as create:
                get_secret.return_value.stdout = json.dumps(existing)
                private.ensure_secret("axiom", "example", {"password": credential}, "Opaque")
                create.assert_not_called()
                get_secret.return_value.stdout = json.dumps({"type": "Opaque", "data": {"password": "bad"}})
                with self.assertRaisesRegex(SystemExit, "refusing replacement"):
                    private.ensure_secret("axiom", "example", {"password": credential}, "Opaque")
                create.assert_not_called()

    def test_missing_secret_is_created_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "password"
            credential.write_text("test-only-password")
            with patch.object(private.subprocess, "run") as get_secret, \
                 patch.object(private, "create_secret") as create:
                get_secret.return_value.stdout = ""
                private.ensure_secret("axiom", "example", {"password": credential}, "Opaque")
                create.assert_called_once_with("axiom", "example", {"password": credential}, "Opaque", False)


if __name__ == "__main__":
    unittest.main()
