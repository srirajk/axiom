#!/usr/bin/env python3
"""Render tests for the Axiom chart: which runtime-Secret keys each workload can read, with which file mode, under
which ServiceAccount, and with what Kubernetes API permissions. Also checks the kind dependency manifest's
PostgreSQL mount. Offline: `helm template` and `kubectl kustomize` only render; no cluster is contacted.

    python3 -B deploy/helm/test_axiom_chart_secret_access.py
"""

from __future__ import annotations

import pathlib
import subprocess
import unittest

import yaml

HERE = pathlib.Path(__file__).resolve().parent
CHART = HERE / "axiom"
REPO = HERE.parent.parent
KIND_DEPENDENCIES = REPO / "deploy" / "kind" / "dependencies.yaml"

DB = "spring.datasource.password"
MASTER = "iam.secrets.master-key"
ADMIN = "axiom.bootstrap.admin-password"
REDIS = "spring.data.redis.password"
S3 = {"iam.policy-studio.runtime.s3.access-key", "iam.policy-studio.runtime.s3.secret-key"}
OWNER_ONLY = 0o400
RBAC_KINDS = {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}


def render(*sets: str) -> list[dict]:
    argv = ["helm", "template", "axiom", str(CHART), "-n", "axiom"]
    for s in sets:
        argv += ["--set", s]
    out = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def pod_spec(doc: dict) -> dict | None:
    if doc["kind"] in ("Deployment", "Job", "StatefulSet"):
        return doc["spec"]["template"]["spec"]
    if doc["kind"] == "Pod":
        return doc["spec"]
    return None


def component(doc: dict) -> str:
    return doc["metadata"]["labels"].get("app.kubernetes.io/component", doc["metadata"]["name"])


class Rendered:
    def __init__(self, docs: list[dict]):
        self.docs = docs
        self.workloads = {component(d): d for d in docs if pod_spec(d) is not None}
        self.accounts = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ServiceAccount"}

    def secret_access(self, name: str, secret: str) -> dict[str, int]:
        """key -> file mode for every projection of ``secret`` into workload ``name``. A volume without ``items``
        would expose every key, represented as '*'."""
        access: dict[str, int] = {}
        for volume in pod_spec(self.workloads[name]).get("volumes", []):
            src = volume.get("secret")
            if not src or src["secretName"] != secret:
                continue
            mode = src.get("defaultMode", 0o644)
            if "items" not in src:
                access["*"] = mode
            for item in src.get("items", []):
                access[item["key"]] = item.get("mode", mode)
        for container in pod_spec(self.workloads[name])["containers"]:
            for env in container.get("env", []):
                ref = env.get("valueFrom", {}).get("secretKeyRef")
                if ref and ref["name"] == secret:
                    access[ref["key"]] = -1  # environment variable
            for env_from in container.get("envFrom", []):
                if env_from.get("secretRef", {}).get("name") == secret:
                    access["*"] = -1
        return access

    def runtime_keys(self, name: str) -> set[str]:
        return set(self.secret_access(name, "axiom-runtime"))


class ChartSecretAccessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.default = Rendered(render())

    # -- runtime Secret keys per workload ---------------------------------------------------------------------------
    def test_server_cannot_read_the_bootstrap_admin_password(self):
        self.assertEqual(self.default.runtime_keys("server"), {DB, MASTER})

    def test_bootstrap_path_gets_exactly_the_server_keys_plus_the_admin_password(self):
        for job in ("bootstrap", "preflight"):
            self.assertEqual(self.default.runtime_keys(job), {DB, MASTER, ADMIN}, job)

    def test_admin_ui_and_test_pods_mount_no_secrets(self):
        for name in ("admin", "verify", "test"):
            spec = pod_spec(self.default.workloads[name])
            self.assertFalse([v for v in spec.get("volumes", []) if "secret" in v], name)
            self.assertEqual(self.default.secret_access(name, "axiom-runtime"), {}, name)

    def test_no_workload_mounts_the_whole_secret_or_uses_secret_environment_variables(self):
        for render_sets in ((), ("redis.passwordEnabled=true",),
                            ("policyRuntime.s3.credentialsFromRuntimeSecret=true",)):
            rendered = Rendered(render(*render_sets))
            for name in rendered.workloads:
                for secret in ("axiom-runtime", "axiom-signing-key"):
                    access = rendered.secret_access(name, secret)
                    self.assertNotIn("*", access, f"{name} mounts all of {secret}")
                    self.assertNotIn(-1, access.values(), f"{name} reads {secret} from the environment")

    def test_optional_credentials_follow_configuration(self):
        redis = Rendered(render("redis.passwordEnabled=true"))
        self.assertEqual(redis.runtime_keys("server"), {DB, MASTER, REDIS})
        self.assertEqual(redis.runtime_keys("bootstrap"), {DB, MASTER, ADMIN, REDIS})
        self.assertEqual(redis.runtime_keys("preflight"), {DB, MASTER, ADMIN, REDIS})

        s3 = Rendered(render("policyRuntime.s3.credentialsFromRuntimeSecret=true"))
        self.assertEqual(s3.runtime_keys("server"), {DB, MASTER} | S3)
        self.assertEqual(s3.runtime_keys("bootstrap"), {DB, MASTER, ADMIN} | S3)

        pvc = Rendered(render("policyRuntime.backend=pvc", "policyRuntime.pvc.existingClaim=runtime",
                              "policyRuntime.s3.credentialsFromRuntimeSecret=true"))
        self.assertEqual(pvc.runtime_keys("server"), {DB, MASTER}, "S3 keys only with the s3 backend")

    def test_renamed_admin_password_key_is_still_excluded_from_the_server(self):
        renamed = Rendered(render("runtimeSecret.keys.adminPassword=custom.admin-password"))
        self.assertNotIn("custom.admin-password", renamed.runtime_keys("server"))
        self.assertIn("custom.admin-password", renamed.runtime_keys("bootstrap"))

    def test_preflight_checks_exactly_the_keys_it_mounts(self):
        for sets in ((), ("redis.passwordEnabled=true",), ("policyRuntime.s3.credentialsFromRuntimeSecret=true",)):
            rendered = Rendered(render(*sets))
            script = pod_spec(rendered.workloads["preflight"])["containers"][0]["args"][0]
            checked = {line.split("/var/run/runtime/")[1].strip() for line in script.splitlines()
                       if "/var/run/runtime/" in line}
            self.assertEqual(checked, rendered.runtime_keys("preflight"), sets)

    def test_projected_file_names_match_the_spring_config_tree(self):
        spec = pod_spec(self.default.workloads["server"])
        container = spec["containers"][0]
        env = {e["name"]: e.get("value") for e in container["env"]}
        mounts = {m["name"]: m for m in container["volumeMounts"]}
        self.assertEqual(env["SPRING_CONFIG_IMPORT"], "configtree:" + mounts["runtime-secret"]["mountPath"] + "/")
        runtime = [v for v in spec["volumes"] if v["name"] == "runtime-secret"][0]["secret"]
        for item in runtime["items"]:
            self.assertEqual(item["path"], item["key"], "file name must be the property name")

    # -- file modes and process users -------------------------------------------------------------------------------
    def test_every_secret_file_is_owner_only_and_readable_by_the_process_group(self):
        for name, doc in self.default.workloads.items():
            spec = pod_spec(doc)
            secret_volumes = [v for v in spec.get("volumes", []) if "secret" in v]
            for volume in secret_volumes:
                src = volume["secret"]
                self.assertEqual(src.get("defaultMode"), OWNER_ONLY, f"{name}/{volume['name']}")
                for item in src.get("items", []):
                    self.assertNotIn("mode", item, "no per-item override widens the mode")
            if secret_volumes:
                ctx = spec["securityContext"]
                # The kubelet adds group read for fsGroup on read-only Secret volumes; the process must run in it.
                self.assertTrue(ctx["runAsNonRoot"], name)
                self.assertEqual(ctx["fsGroup"], ctx["runAsGroup"], name)
                for container in spec["containers"]:
                    for mount in container.get("volumeMounts", []):
                        if mount["name"] in {v["name"] for v in secret_volumes}:
                            self.assertTrue(mount.get("readOnly"), f"{name}/{mount['name']}")

    # -- ServiceAccounts and permissions ----------------------------------------------------------------------------
    def test_each_component_has_its_own_service_account(self):
        expected = {"server": "axiom", "bootstrap": "axiom-bootstrap", "preflight": "axiom-preflight",
                    "admin": "axiom-admin", "verify": "axiom-test", "test": "axiom-test"}
        actual = {name: pod_spec(doc).get("serviceAccountName") for name, doc in self.default.workloads.items()}
        self.assertEqual(actual, expected)
        server_users = [n for n, sa in actual.items() if sa == "axiom"]
        self.assertEqual(server_users, ["server"], "only the server uses the server ServiceAccount")
        for account in set(expected.values()):
            self.assertIn(account, self.default.accounts, f"{account} is rendered")

    def test_no_token_automount_and_no_rbac(self):
        for name, account in self.default.accounts.items():
            self.assertIs(account.get("automountServiceAccountToken"), False, name)
        for name, doc in self.default.workloads.items():
            self.assertIs(pod_spec(doc).get("automountServiceAccountToken"), False, name)
        self.assertFalse([d for d in self.default.docs if d["kind"] in RBAC_KINDS], "chart grants no API permissions")

    def test_hook_service_accounts_exist_before_their_jobs(self):
        def weight(doc):
            return int(doc["metadata"].get("annotations", {}).get("helm.sh/hook-weight", "0"))

        for job in ("bootstrap", "preflight"):
            doc = self.default.workloads[job]
            account = self.default.accounts[pod_spec(doc)["serviceAccountName"]]
            ann = account["metadata"]["annotations"]
            self.assertEqual(ann["helm.sh/hook"], doc["metadata"]["annotations"]["helm.sh/hook"])
            self.assertLess(weight(account), weight(doc))
            # Helm deletes hook-succeeded resources only after the whole phase succeeds (pkg/action/hooks.go),
            # so the account outlives both Jobs and then goes; before-hook-creation replaces a leftover on retry.
            self.assertEqual(set(ann["helm.sh/hook-delete-policy"].split(",")),
                             {"before-hook-creation", "hook-succeeded"})
            self.assertEqual(doc["metadata"]["annotations"]["helm.sh/hook"], "pre-install,pre-upgrade")
        jobs = [d for d in self.default.workloads.values() if d["kind"] == "Job"
                and "pre-install" in d["metadata"]["annotations"]["helm.sh/hook"]]
        self.assertEqual(sorted(component(j) for j in jobs), ["bootstrap", "preflight"],
                         "no other pre-install hook can outlive the accounts' deletion")
        for name in ("axiom", "axiom-admin", "axiom-test"):
            self.assertNotIn("helm.sh/hook", self.default.accounts[name]["metadata"].get("annotations") or {}, name)

    def test_workload_identity_annotations_stay_on_their_own_account(self):
        rendered = Rendered(render("serviceAccount.annotations.role=server-role",
                                   "serviceAccount.bootstrap.annotations.role=bootstrap-role"))
        roles = {name: (acc["metadata"].get("annotations") or {}).get("role") for name, acc in rendered.accounts.items()}
        self.assertEqual(roles, {"axiom": "server-role", "axiom-bootstrap": "bootstrap-role", "axiom-admin": None,
                                 "axiom-preflight": None, "axiom-test": None})

    def test_service_accounts_disabled_fall_back_without_sharing_the_server_name(self):
        rendered = Rendered(render("serviceAccount.create=false", "serviceAccount.name=server-sa"))
        self.assertEqual(rendered.accounts, {})
        names = {n: pod_spec(d).get("serviceAccountName") for n, d in rendered.workloads.items()}
        self.assertEqual(names["server"], "server-sa")
        self.assertEqual({v for k, v in names.items() if k != "server"}, {"default"})

    def test_annotated_hook_accounts_are_also_removed_on_success(self):
        rendered = Rendered(render("serviceAccount.bootstrap.annotations.role=bootstrap-role"))
        ann = rendered.accounts["axiom-bootstrap"]["metadata"]["annotations"]
        self.assertEqual(ann["role"], "bootstrap-role")
        self.assertIn("hook-succeeded", ann["helm.sh/hook-delete-policy"])

    # -- runtimeSecret.keys validation ------------------------------------------------------------------------------
    def assert_render_fails(self, *sets: str, message: str):
        argv = ["helm", "template", "axiom", str(CHART), "-n", "axiom"]
        for s in sets:
            argv += ["--set", s]
        result = subprocess.run(argv, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, f"render must fail for {sets}")
        self.assertIn(message, result.stderr, result.stderr)
        self.assertEqual(result.stdout, "", "nothing rendered")

    def test_admin_password_cannot_alias_any_server_projected_key(self):
        server_roles = {"databasePassword": DB, "masterKey": MASTER, "redisPassword": REDIS,
                        "s3AccessKey": "iam.policy-studio.runtime.s3.access-key",
                        "s3SecretKey": "iam.policy-studio.runtime.s3.secret-key"}
        for role, key in server_roles.items():
            for features in ((), ("redis.passwordEnabled=true",
                                  "policyRuntime.s3.credentialsFromRuntimeSecret=true")):
                self.assert_render_fails(f"runtimeSecret.keys.adminPassword={key}", *features,
                                         message=f"both name Secret key \"{key}\"")

    def test_any_duplicate_role_key_is_rejected(self):
        self.assert_render_fails(f"runtimeSecret.keys.masterKey={DB}", message="each role needs its own key")
        self.assert_render_fails("runtimeSecret.keys.s3AccessKey=shared", "runtimeSecret.keys.s3SecretKey=shared",
                                 message="each role needs its own key")
        self.assert_render_fails(f"runtimeSecret.keys.redisPassword={ADMIN}", message="each role needs its own key")

    def test_empty_or_unsafe_key_names_are_rejected(self):
        self.assert_render_fails("runtimeSecret.keys.adminPassword=", message="runtimeSecret.keys.adminPassword is required")
        for bad in ("../escape", "a/b", "..", "has space"):
            self.assert_render_fails(f"runtimeSecret.keys.adminPassword={bad}", message="not a valid Secret key name")

    def test_distinct_custom_key_names_render(self):
        rendered = Rendered(render("runtimeSecret.keys.adminPassword=bootstrap-admin",
                                   "runtimeSecret.keys.databasePassword=db"))
        self.assertEqual(rendered.runtime_keys("server"), {"db", MASTER})
        self.assertEqual(rendered.runtime_keys("bootstrap"), {"db", MASTER, "bootstrap-admin"})

    # -- kind PostgreSQL ---------------------------------------------------------------------------------------------
    def test_kind_postgresql_reads_only_the_database_password(self):
        docs = [d for d in yaml.safe_load_all(KIND_DEPENDENCIES.read_text()) if d]
        statefulset = [d for d in docs if d["kind"] == "StatefulSet"
                       and d["metadata"]["name"] == "axiom-postgresql"][0]
        rendered = Rendered([statefulset])
        name = component(statefulset)
        self.assertEqual(rendered.secret_access(name, "axiom-runtime"), {DB: OWNER_ONLY})
        spec = pod_spec(statefulset)
        self.assertEqual(spec["securityContext"]["fsGroup"], spec["securityContext"]["runAsUser"])
        env = {e["name"]: e.get("value") for e in spec["containers"][0]["env"]}
        mount = [m for m in spec["containers"][0]["volumeMounts"] if m["name"] == "runtime-secret"][0]
        self.assertEqual(env["POSTGRES_PASSWORD_FILE"], mount["mountPath"])
        self.assertEqual(mount["subPath"], DB)

    def test_isolated_overlay_inherits_the_narrowed_postgresql_mount(self):
        # The overlay includes ../kind/dependencies.yaml, so it builds only without the default load restrictor.
        out = subprocess.run(["kubectl", "kustomize", "--load-restrictor", "LoadRestrictionsNone",
                              str(REPO / "deploy" / "phase0-isolated")], check=True,
                             capture_output=True, text=True).stdout
        docs = [d for d in yaml.safe_load_all(out) if d]
        statefulset = [d for d in docs if d["kind"] == "StatefulSet"
                       and d["metadata"]["name"] == "axiom-postgresql"][0]
        self.assertEqual(Rendered([statefulset]).secret_access(component(statefulset), "axiom-runtime"),
                         {DB: OWNER_ONLY})
        self.assertEqual(statefulset["metadata"]["namespace"], "axiom-phase0-test")


if __name__ == "__main__":
    unittest.main()
