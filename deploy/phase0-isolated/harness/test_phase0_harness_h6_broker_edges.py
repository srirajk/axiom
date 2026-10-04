#!/opt/homebrew/bin/python3.13
"""Offline tests for phase0_harness_h6_broker_edges.py: no Docker, Java, network or cluster access."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import unittest

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase0_harness_h6_broker_edges.py")
_spec = importlib.util.spec_from_file_location("phase0_harness_h6_broker_edges", _PATH)
h6 = importlib.util.module_from_spec(_spec)
sys.modules["phase0_harness_h6_broker_edges"] = h6
_spec.loader.exec_module(h6)


class FakeRun:
    """Records argv and answers the docker calls LocalStack makes."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.ps_results = [["c1", "c2", "c3"], []]

    def __call__(self, argv, timeout, env=None):
        self.calls.append(list(argv))
        out = ""
        if "run" in argv:
            out = f"{argv[argv.index('--label') + 3].split('=')[-1]}-cid\n"
        elif "port" in argv:
            out = "127.0.0.1:50001\n"
        elif "logs" in argv:
            out = "database system is ready to accept connections\n" * 2
        elif "ps" in argv:
            out = "\n".join(self.ps_results.pop(0) if self.ps_results else [])
        return subprocess.CompletedProcess(argv, 0, out, "")


class ExpectationTableTest(unittest.TestCase):
    def test_h2_cases_are_kept_unchanged_and_in_order(self):
        h2_order = h6.h2.H2_EXPECTATIONS["order"]
        order = h6.H6_EXPECTATIONS["order"]
        self.assertEqual([c for c in order if c.startswith("H2-")], h2_order)
        for cid in h2_order:
            self.assertEqual(h6.H6_EXPECTATIONS["cases"][cid], h6.h2.H2_EXPECTATIONS["cases"][cid])

    def test_every_added_case_is_a_denial_ordered_before_the_positive_redemption_of_its_subject(self):
        order = h6.H6_EXPECTATIONS["order"]
        cases = h6.H6_EXPECTATIONS["cases"]
        added = [c for c in order if c.startswith("H6-")]
        self.assertEqual(len(added), 16)
        # Broker-edge subjects and the positive case that redeems each of them.
        redeemed_by = {"H2-P3": "H2-P4", "H2-P4": "H2-P5", "H2-P5": "H2-P6"}
        for cid in added:
            spec = cases[cid]
            self.assertIn("denial", spec)
            self.assertNotIn("checks", spec)
            self.assertEqual(spec["denial"]["status"], 400)
            self.assertEqual(spec["depends"], [spec["subject"]])
            positive = redeemed_by.get(spec["subject"])
            if positive is not None:
                self.assertLess(order.index(cid), order.index(positive), cid)

    def test_both_named_edges_cover_all_four_denial_classes(self):
        cases = h6.H6_EXPECTATIONS["cases"]
        for edge in ("H6-A", "H6-R"):
            classes = {cases[c]["class"] for c in cases if c.startswith(edge)}
            self.assertTrue({"wrong_token_use", "wrong_redeemer", "over_broad_scope", "wrong_destination"} <= classes,
                            edge)

    def test_route_claim_states_fixture_scope(self):
        self.assertIn("fixture", h6.ROUTE_CLAIM)
        self.assertIn("do not claim Phase 1", h6.ROUTE_CLAIM)


class PlanModeTest(unittest.TestCase):
    def test_plan_mode_runs_no_subprocess(self):
        original = subprocess.run, subprocess.Popen

        def forbidden(*a, **k):
            raise AssertionError("subprocess used in plan mode")

        subprocess.run, subprocess.Popen = forbidden, forbidden
        try:
            out = io.StringIO()
            self.assertEqual(h6.main(["--package", "h6"], out=out), 0)
        finally:
            subprocess.run, subprocess.Popen = original
        events = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertTrue(all(e["event"].startswith("h6_") and e["package"] == "H-6" for e in events))
        planned = [e["case_id"] for e in events if e["event"] == "h6_plan_case"]
        self.assertEqual(planned, h6.H6_EXPECTATIONS["order"])
        self.assertIn("route_claim", events[0])


class RunnerTest(unittest.TestCase):
    def runner(self, out):
        return h6.H6Runner(out=out, stack_factory=lambda p: h6.LocalStack(p, run=FakeRun()))

    def test_cluster_tools_are_refused(self):
        r = self.runner(io.StringIO())
        with self.assertRaises(h6.HarnessError):
            r.run_cmd(["kubectl", "get", "ns"], 1.0)
        with self.assertRaises(h6.HarnessError):
            r.popen(["kubectl", "port-forward"])
        with self.assertRaises(h6.HarnessError):
            h6.default_run(["helm", "list"], 1.0)

    def test_events_are_renamed_and_run_start_records_deviations(self):
        out = io.StringIO()
        r = self.runner(out)
        r.emit({"event": "h2_run_start", "context": "docker-desktop", "namespace": "axiom-phase0-test"})
        r.emit({"event": "case", "package": "H-2"})
        first, second = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertEqual(first["event"], "h6_run_start")
        self.assertEqual(first["context"], "local-disposable")
        self.assertIsNone(first["namespace"])
        self.assertEqual(len(first["deviations"]), len(h6.DEVIATIONS))
        self.assertEqual(second, {"event": "h6_case", "package": "H-6"})


class LocalStackTest(unittest.TestCase):
    def test_secrets_are_private_files_and_never_in_argv_or_environment(self):
        run = FakeRun()
        stack = h6.LocalStack("p0htest", run=run, sleep=lambda s: None)
        try:
            modes = stack.make_workdir()
            self.assertEqual(modes["workdir_mode"], "0o700")
            self.assertEqual(set(modes["secret_file_modes"].values()), {"0o600"})
            stack.start_containers()
            values = [stack.secret(n) for n in h6.SECRET_FILES]
            flat_argv = " ".join(" ".join(c) for c in run.calls)
            env = stack.server_env("http://127.0.0.1:42000")
            for v in values:
                self.assertNotIn(v, flat_argv)
                self.assertNotIn(v, " ".join(env.values()))
            self.assertIn("POSTGRES_PASSWORD_FILE=/run/axiom/db-password", flat_argv)
            self.assertTrue(env["SPRING_CONFIG_IMPORT"].startswith("configtree:"))
            for call in run.calls:
                if "run" in call:
                    published = [call[i + 1] for i, a in enumerate(call) if a == "-p"]
                    self.assertTrue(published and all(p.startswith("127.0.0.1::") for p in published), call)
                    self.assertIn(f"{h6.LABEL_KEY}=p0htest", call)
        finally:
            result = stack.teardown()
        self.assertEqual(result["containers_removed"], 3)
        self.assertEqual(result["containers_remaining"], 0)
        self.assertTrue(result["workdir_removed"])
        self.assertFalse(os.path.exists(stack.workdir))
        self.assertIn(["docker", "rm", "-f", "-v", "c1", "c2", "c3"],
                      [[os.path.basename(c[0]), *c[1:]] for c in run.calls])

    def test_port_must_be_loopback(self):
        stack = h6.LocalStack("p0htest", run=lambda argv, timeout, env=None:
                              subprocess.CompletedProcess(argv, 0, "0.0.0.0:50001\n", ""))
        stack.containers["redis"] = "cid"
        with self.assertRaises(h6.AbortRun):
            stack._port("redis", 6379)



# ---------------------------------------------------------------------------------------------------------------------
# Fault injection: a stateful fake Docker daemon and fake JVM processes
# ---------------------------------------------------------------------------------------------------------------------

UNRELATED_LABEL = "other.project=keep"


class FakeDocker:
    """Holds containers and volumes like the daemon would. ``faults`` maps an event name to a callable that may raise
    or return a replacement CompletedProcess. Starts with one unrelated container and volume that must survive."""

    def __init__(self, faults: dict | None = None):
        self.faults = faults or {}
        self.containers: dict[str, dict] = {"unrelated-c": {"labels": {UNRELATED_LABEL}, "volumes": ["unrelated-v"]}}
        self.volumes: dict[str, set] = {"unrelated-v": {UNRELATED_LABEL}}
        self.calls: list[list[str]] = []
        self.counts: dict[str, int] = {}
        self.masks: list[set] = []
        self.n = 0

    def _fault(self, name: str, argv: list[str]):
        self.counts[name] = self.counts.get(name, 0) + 1
        fn = self.faults.get(name)
        return fn(self.counts[name], argv) if fn else None

    @staticmethod
    def ok(argv, out="", rc=0, err=""):
        return subprocess.CompletedProcess(argv, rc, out, err)

    def __call__(self, argv, timeout, env=None):
        argv = list(argv)
        self.calls.append(argv)
        if argv[0] == h6.JAVA:
            return self.ok(argv, err='openjdk version "25.0.3" 2026-04-21\n')
        verb = argv[1:3] if argv[1] in ("image", "volume") else argv[1:2]
        name = " ".join(verb)
        if name in ("rm", "volume rm", "ps", "volume ls"):
            self.masks.append(set(signal.pthread_sigmask(signal.SIG_BLOCK, [])))
        replaced = self._fault(name, argv)
        if replaced is not None:
            return replaced
        if name == "version":
            return self.ok(argv, "29.8.0\n")
        if name == "image inspect":
            return self.ok(argv, "sha256:fake\n")
        if name == "run":
            labels = {argv[i + 1] for i, a in enumerate(argv) if a == "--label"}
            vols = []
            for i, a in enumerate(argv):
                if a == "--mount":
                    spec = dict(kv.split("=", 1) for kv in argv[i + 1].split(","))
                    self.volumes.setdefault(spec["src"], set()).add(spec["volume-label"])
                    vols.append(spec["src"])
            self.n += 1
            cid = f"c{self.n}"
            self.containers[cid] = {"labels": labels, "volumes": vols}
            after = self._fault("run-created", argv)
            if after is not None:
                return after
            return self.ok(argv, cid + "\n")
        if name == "port":
            return self.ok(argv, "127.0.0.1:50001\n")
        if name == "logs":
            return self.ok(argv, "database system is ready to accept connections\n" * 2)
        if name == "ps":
            label = argv[argv.index("--filter") + 1].split("=", 1)[1]
            return self.ok(argv, "\n".join(c for c, v in self.containers.items() if label in v["labels"]))
        if name == "rm":
            for cid in argv[4:]:
                self.containers.pop(cid, None)
            return self.ok(argv)
        if name == "volume ls":
            label = argv[argv.index("--filter") + 1].split("=", 1)[1]
            return self.ok(argv, "\n".join(v for v, ls in self.volumes.items() if label in ls))
        if name == "volume rm":
            in_use = {v for c in self.containers.values() for v in c["volumes"]}
            for v in argv[4:]:
                if v not in in_use:
                    self.volumes.pop(v, None)
            return self.ok(argv)
        raise AssertionError(f"unexpected docker call {argv}")

    def owned(self, prefix: str) -> tuple[list, list]:
        label = f"{h6.LABEL_KEY}={prefix}"
        return ([c for c, v in self.containers.items() if label in v["labels"]],
                [v for v, ls in self.volumes.items() if label in ls])


class FakeProc:
    def __init__(self, rc_on_exit=0, wait_fault=None):
        self.rc = None
        self.rc_on_exit = rc_on_exit
        self.wait_fault = wait_fault
        self.terminated = self.killed = 0

    def poll(self):
        return self.rc

    def wait(self, timeout=None):
        if self.wait_fault is not None:
            fault, self.wait_fault = self.wait_fault, None
            raise fault
        if self.rc is None and self.rc_on_exit is not None:
            self.rc = self.rc_on_exit
        if self.rc is None:
            raise subprocess.TimeoutExpired("java", timeout)
        return self.rc

    def terminate(self):
        self.terminated += 1
        self.rc = -15

    def kill(self):
        self.killed += 1
        self.rc = -9


class FaultInjectionTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="h6-fault-test-")
        jar = os.path.join(self.tmp, "app.jar")
        with open(jar, "wb") as fh:
            fh.write(b"jar")
        src = os.path.join(self.tmp, "server", "src", "main")
        os.makedirs(src)
        with open(os.path.join(src, "A.java"), "w") as fh:
            fh.write("class A {}")
        os.utime(os.path.join(src, "A.java"), (0, 0))
        self.saved = (h6.JAR_PATH, h6.SERVER_DIR)
        h6.JAR_PATH, h6.SERVER_DIR = jar, os.path.join(self.tmp, "server")
        self.parent = os.path.join(self.tmp, "work")
        os.mkdir(self.parent)

    def tearDown(self):
        import shutil
        h6.JAR_PATH, h6.SERVER_DIR = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_h6(self, docker, *, procs=None, port=42001, stack_cls=None):
        procs = list(procs or [])
        self.stacks = []

        def popen(argv, **kw):
            return procs.pop(0) if procs else FakeProc()

        def factory(prefix):
            stack = (stack_cls or h6.LocalStack)(prefix, run=docker, popen=popen, workdir_parent=self.parent,
                                                 sleep=lambda s: None)
            self.stacks.append(stack)
            return stack

        out = io.StringIO()
        runner = h6.H6Runner(out=out, stack_factory=factory, port_chooser=lambda: port)
        rc = runner.run()
        events = [json.loads(l) for l in out.getvalue().splitlines()]
        return runner, rc, events

    def assert_clean(self, runner, docker, events, *, expect_rc=2, rc=None):
        stack = self.stacks[0]
        containers, volumes = docker.owned(runner.prefix)
        self.assertEqual(containers, [], "labelled containers left")
        self.assertEqual(volumes, [], "labelled volumes left")
        if stack.workdir is not None:
            self.assertFalse(os.path.exists(stack.workdir), "work directory left")
        self.assertEqual(os.listdir(self.parent), [])
        self.assertIn("unrelated-c", docker.containers)
        self.assertIn("unrelated-v", docker.volumes)
        teardowns = [e for e in events if e["event"] == "h6_teardown"]
        self.assertEqual(len(teardowns), 1, "teardown must be reported exactly once")
        self.assertTrue(teardowns[0]["ok"], teardowns[0])
        for call in docker.calls:  # only this run's labelled ids are ever removed
            if call[1] == "rm" or call[1:3] == ["volume", "rm"]:
                self.assertNotIn("unrelated-c", call)
                self.assertNotIn("unrelated-v", call)
        if rc is not None:
            self.assertEqual(rc, expect_rc)
        return teardowns[0]

    def test_failure_during_workdir_creation(self):
        class FailingSecrets(h6.LocalStack):
            def make_workdir(self):
                original = h6.secrets.token_urlsafe
                h6.secrets.token_urlsafe = lambda n: (_ for _ in ()).throw(OSError("disk full"))
                try:
                    return super().make_workdir()
                finally:
                    h6.secrets.token_urlsafe = original

        docker = FakeDocker()
        runner, rc, events = self.run_h6(docker, stack_cls=FailingSecrets)
        self.assertIsNotNone(self.stacks[0].workdir)
        self.assert_clean(runner, docker, events, rc=rc)
        self.assertTrue(runner.aborted)

    def test_partial_container_startup_second_run_fails(self):
        docker = FakeDocker({"run": lambda n, argv: FakeDocker.ok(argv, rc=125, err="boom") if n == 2 else None})
        runner, rc, events = self.run_h6(docker)
        td = self.assert_clean(runner, docker, events, rc=rc)
        self.assertEqual(td["containers_removed"], 1)
        self.assertEqual(td["volumes_removed"], 1)

    def test_container_created_but_docker_run_times_out(self):
        def created(n, argv):
            if n == 3:
                raise subprocess.TimeoutExpired(argv, 60)
        docker = FakeDocker({"run-created": created})
        runner, rc, events = self.run_h6(docker)
        td = self.assert_clean(runner, docker, events, rc=rc)
        self.assertEqual(td["containers_removed"], 3, "the container whose id was never returned is found by label")

    def test_port_bound_beyond_loopback(self):
        docker = FakeDocker({"port": lambda n, argv: FakeDocker.ok(argv, "0.0.0.0:50001\n") if n == 3 else None})
        runner, rc, events = self.run_h6(docker)
        td = self.assert_clean(runner, docker, events, rc=rc)
        self.assertEqual(td["containers_removed"], 3)
        self.assertEqual(td["volumes_removed"], 5)

    def test_no_free_harness_port(self):
        docker = FakeDocker()
        runner, rc, events = self.run_h6(docker, port=None)
        self.assert_clean(runner, docker, events, rc=rc)
        self.assertIn("V-6", runner.abort_reason)

    def test_interrupt_while_containers_start(self):
        def interrupt(n, argv):
            raise KeyboardInterrupt
        docker = FakeDocker({"logs": interrupt})
        runner, rc, events = self.run_h6(docker)
        self.assert_clean(runner, docker, events, rc=rc)
        self.assertEqual(runner.abort_reason, "interrupted")

    def test_interrupt_during_bootstrap_stops_the_jvm(self):
        bootstrap = FakeProc(rc_on_exit=None, wait_fault=KeyboardInterrupt())
        docker = FakeDocker()
        runner, rc, events = self.run_h6(docker, procs=[bootstrap])
        self.assert_clean(runner, docker, events, rc=rc)
        self.assertEqual(bootstrap.terminated, 1)
        self.assertIsNotNone(bootstrap.poll())

    def test_bootstrap_failure_exit_code(self):
        docker = FakeDocker()
        runner, rc, events = self.run_h6(docker, procs=[FakeProc(rc_on_exit=1)])
        self.assert_clean(runner, docker, events, rc=rc)
        self.assertIn("bootstrap failed", runner.abort_reason)

    def test_interrupt_between_steps_outside_guards_is_caught_by_run(self):
        original = h6.h2.H2Runner.run

        def interrupted_run(self):
            self.v1_context()
            self.v2_namespace()
            self.v3_release()
            raise KeyboardInterrupt  # lands between steps, outside every guard and H-2 handler

        h6.h2.H2Runner.run = interrupted_run
        try:
            docker = FakeDocker()
            runner, rc, events = self.run_h6(docker)
        finally:
            h6.h2.H2Runner.run = original
        td = self.assert_clean(runner, docker, events, rc=rc)
        self.assertEqual(td["containers_removed"], 3)
        self.assertTrue(runner.aborted)

    def test_interrupt_inside_teardown_is_retried_and_reported(self):
        def interrupt_once(n, argv):
            if n == 1:
                raise KeyboardInterrupt
        docker = FakeDocker({"run": lambda n, argv: FakeDocker.ok(argv, rc=125) if n == 3 else None,
                             "rm": interrupt_once})
        runner, rc, events = self.run_h6(docker)
        td = [e for e in events if e["event"] == "h6_teardown"][0]
        self.assertTrue(td["interrupted"])
        self.assertEqual(docker.owned(runner.prefix), ([], []))
        self.assertEqual(rc, 2)

    def test_teardown_defers_signals(self):
        docker = FakeDocker({"run": lambda n, argv: FakeDocker.ok(argv, rc=125) if n == 2 else None})
        runner, rc, events = self.run_h6(docker)
        self.assert_clean(runner, docker, events, rc=rc)
        self.assertTrue(docker.masks)
        for mask in docker.masks:
            self.assertTrue({signal.SIGINT, signal.SIGTERM, signal.SIGHUP} <= mask)
        self.assertFalse({signal.SIGINT, signal.SIGTERM} & set(signal.pthread_sigmask(signal.SIG_BLOCK, [])))

    def test_unverifiable_teardown_fails_the_run(self):
        def ps_timeout(n, argv):
            raise subprocess.TimeoutExpired(argv, 60)
        docker = FakeDocker({"run": lambda n, argv: FakeDocker.ok(argv, rc=125) if n == 2 else None,
                             "ps": ps_timeout})
        runner, rc, events = self.run_h6(docker)
        td = [e for e in events if e["event"] == "h6_teardown"][0]
        self.assertFalse(td["ok"])
        self.assertIsNone(td["containers_remaining"])
        self.assertEqual(rc, 2)
        summary = [e for e in events if e["event"] == "h6_summary"][0]
        self.assertTrue(summary["port_forward_leaked"])

    def test_teardown_is_idempotent(self):
        docker = FakeDocker()
        stack = h6.LocalStack("p0hidem", run=docker, popen=lambda *a, **k: FakeProc(), workdir_parent=self.parent,
                              sleep=lambda s: None)
        stack.make_workdir()
        stack.start_containers()
        server = FakeProc(rc_on_exit=None)
        stack.server = server
        first = stack.teardown()
        calls = len(docker.calls)
        self.assertIs(stack.teardown(), first)
        self.assertEqual(len(docker.calls), calls)
        self.assertTrue(first["ok"])
        self.assertEqual(server.terminated, 1)
        self.assertEqual(docker.owned("p0hidem"), ([], []))


if __name__ == "__main__":
    unittest.main()
