#!/usr/bin/env python3
"""Offline tests for deploy/helm/recover_hook_service_accounts.py. kubectl is an in-memory fake; `helm template`
renders locally to check the name derivation against the chart."""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout

import yaml

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("recover", HERE / "recover_hook_service_accounts.py")
recover = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recover)


def hook_account(name, component, release="axiom", annotations=None, hook="pre-install,pre-upgrade"):
    ann = {"helm.sh/hook": hook, "helm.sh/hook-weight": "-30",
           "helm.sh/hook-delete-policy": "before-hook-creation,hook-succeeded", **(annotations or {})}
    if hook is None:
        ann.pop("helm.sh/hook")
    return {"metadata": {"name": name, "uid": f"uid-{name}", "annotations": ann,
                         "labels": {"app.kubernetes.io/instance": release, "app.kubernetes.io/managed-by": "Helm",
                                    "app.kubernetes.io/name": "axiom", "app.kubernetes.io/component": component}}}


class FakeCluster:
    def __init__(self, accounts=(), pods=(), jobs=(), fail_get=None):
        self.accounts = {a["metadata"]["name"]: a for a in accounts}
        self.pods, self.jobs = list(pods), list(jobs)
        self.fail_get = fail_get
        self.calls: list[list[str]] = []

    def __call__(self, argv, capture_output=False, text=False, **kw):
        self.calls.append(list(argv))
        assert argv[0] == "kubectl", argv
        verb, kind = argv[1], argv[2]
        self.assertion_no_secrets(argv)
        if verb == "get":
            if self.fail_get == kind:
                return subprocess.CompletedProcess(argv, 1, "", "Error from server (Forbidden)")
            if kind == "serviceaccount":
                obj = self.accounts.get(argv[3])
                return subprocess.CompletedProcess(argv, 0, json.dumps(obj) if obj else "", "")
            items = self.pods if kind == "pods" else self.jobs
            return subprocess.CompletedProcess(argv, 0, json.dumps({"items": items}), "")
        if verb == "delete" and kind == "serviceaccount":
            self.accounts.pop(argv[3], None)
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    @staticmethod
    def assertion_no_secrets(argv):
        assert "secret" not in argv and "secrets" not in argv, "never reads Secrets"
        assert not any(a.startswith("-l") or a.startswith("--selector") for a in argv), "never uses selectors"


def pod(name, sa, phase="Running"):
    return {"metadata": {"name": name}, "spec": {"serviceAccountName": sa}, "status": {"phase": phase}}


def job(name, sa, active=1):
    return {"metadata": {"name": name}, "spec": {"template": {"spec": {"serviceAccountName": sa}}},
            "status": {"active": active} if active else {}}


class RecoveryTest(unittest.TestCase):
    def run_tool(self, cluster, *args):
        saved = recover.subprocess.run
        recover.subprocess.run = cluster
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = recover.main(["-n", "axiom", "--release", "axiom", *args])
        finally:
            recover.subprocess.run = saved
        lines = [json.loads(l) for l in out.getvalue().splitlines()]
        return rc, lines, err.getvalue()

    def deletes(self, cluster):
        return [c[3] for c in cluster.calls if c[1] == "delete"]

    def test_plan_is_read_only_and_redacts_annotation_values(self):
        cluster = FakeCluster([hook_account("axiom-bootstrap", "bootstrap",
                                            annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/x"})])
        rc, lines, _ = self.run_tool(cluster)
        self.assertEqual(rc, 0)
        plan = {p["name"]: p for p in lines[0]["plan"]}
        self.assertEqual(plan["axiom-bootstrap"]["action"], "delete")
        self.assertEqual(plan["axiom-bootstrap"]["extra_annotation_keys"], ["eks.amazonaws.com/role-arn"])
        self.assertNotIn("arn:aws", json.dumps(lines))
        self.assertEqual(plan["axiom-preflight"], {"name": "axiom-preflight", "action": "none", "reason": "absent"})
        self.assertEqual(self.deletes(cluster), [])

    def test_execute_deletes_exactly_the_leftover_hook_accounts(self):
        unrelated = [hook_account("axiom", "server"), hook_account("axiom-admin", "admin"),
                     hook_account("other-axiom-bootstrap", "bootstrap", release="other"),
                     hook_account("axiom-bootstrap-old", "bootstrap")]
        cluster = FakeCluster([hook_account("axiom-bootstrap", "bootstrap"),
                               hook_account("axiom-preflight", "preflight"), *unrelated],
                              pods=[pod("axiom-bootstrap-x", "axiom-bootstrap", phase="Failed")],
                              jobs=[job("axiom-bootstrap", "axiom-bootstrap", active=0)])
        rc, lines, _ = self.run_tool(cluster, "--execute")
        self.assertEqual(rc, 0)
        self.assertEqual(self.deletes(cluster), ["axiom-bootstrap", "axiom-preflight"])
        self.assertEqual(sorted(cluster.accounts), sorted(a["metadata"]["name"] for a in unrelated))
        self.assertEqual([l["name"] for l in lines if l.get("deleted")], ["axiom-bootstrap", "axiom-preflight"])

    def test_refuses_accounts_that_are_not_this_releases_hooks(self):
        cases = [hook_account("axiom-bootstrap", "bootstrap", release="other"),
                 hook_account("axiom-bootstrap", "server"),
                 hook_account("axiom-bootstrap", "bootstrap", hook=None),
                 hook_account("axiom-bootstrap", "bootstrap", hook="post-install")]
        for account in cases:
            cluster = FakeCluster([account])
            rc, lines, _ = self.run_tool(cluster, "--execute")
            self.assertEqual(rc, 2, account)
            self.assertEqual(self.deletes(cluster), [], account)

    def test_refuses_while_a_running_pod_or_active_job_uses_the_account(self):
        for kw in ({"pods": [pod("p", "axiom-preflight")]}, {"jobs": [job("axiom-preflight", "axiom-preflight")]}):
            cluster = FakeCluster([hook_account("axiom-bootstrap", "bootstrap"),
                                   hook_account("axiom-preflight", "preflight")], **kw)
            rc, lines, _ = self.run_tool(cluster, "--execute")
            self.assertEqual(rc, 2)
            self.assertIn("in use by", json.dumps(lines))
            self.assertEqual(self.deletes(cluster), [], "nothing deleted when any target is refused")

    def test_kubectl_failure_refuses_without_deleting(self):
        cluster = FakeCluster([hook_account("axiom-bootstrap", "bootstrap")], fail_get="pods")
        rc, _, err = self.run_tool(cluster, "--execute")
        self.assertEqual(rc, 2)
        self.assertIn("Forbidden", err)
        self.assertEqual(self.deletes(cluster), [])

    def test_names_match_the_chart_for_release_name_variants(self):
        for release, extra, cli in (("axiom", [], []), ("prod", [], []), ("my-axiom", [], []),
                                    ("prod", ["fullnameOverride=idp"], ["idp", ""]),
                                    ("prod", ["nameOverride=identity"], ["", "identity"])):
            argv = ["helm", "template", release, str(HERE / "axiom"), "-n", "ns"]
            for e in extra:
                argv += ["--set", e]
            docs = [d for d in yaml.safe_load_all(subprocess.run(argv, check=True, capture_output=True,
                                                                 text=True).stdout) if d]
            rendered = {d["metadata"]["labels"]["app.kubernetes.io/component"]: d["metadata"]["name"]
                        for d in docs if d["kind"] == "ServiceAccount"}
            base = recover.fullname(release, *(cli or ["", ""]))
            self.assertEqual(rendered["bootstrap"], f"{base}-bootstrap", release)
            self.assertEqual(rendered["preflight"], f"{base}-preflight", release)


if __name__ == "__main__":
    unittest.main()
