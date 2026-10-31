#!/usr/bin/env python3
"""Repeatable, non-destructive installer for the disposable Docker Desktop Axiom estate.

Like the Argus installer, planning and rendering are separate from installation.
This profile never deletes namespaces, PVCs, credentials, or an existing release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTEXT = "docker-desktop"
BRANCH = "hardening/phase-0-baseline"
ENVOY_CHART = "oci://docker.io/envoyproxy/gateway-helm"
ENVOY_VERSION = "v1.9.1"
EDGE_RELEASE = "axiom-local-edge"
EDGE_CHART = ROOT / "deploy/helm/axiom-local-edge"
ADMIN_BUILD_ARGS = (
    "VITE_AXIOM_ISSUER=https://identity.meridian.com",
    "VITE_AXIOM_API_URL=https://identity.meridian.com",
    "VITE_CIAM_TENANT_ID=meridian",
    "VITE_CIAM_CUSTOMER_CLIENT_ID=demo-customer-web",
    "VITE_CIAM_CUSTOMER_SCOPES=example:read",
)
PRIVATE_FILES = (
    "certs/local-ca.crt", "certs/local-ca.key", "certs/axiom-identity.crt",
    "certs/axiom-identity.key", "certs/axiom-admin.crt", "certs/axiom-admin.key",
    "certs/signing-key.json", "certs/jwks.json", "passwords/axiom-admin-username",
    "passwords/axiom-admin-password", "passwords/postgres-password", "passwords/axiom-master-key",
)


class InstallError(RuntimeError):
    pass


def run(*args: str, input_data: str | None = None, show: bool = False) -> str:
    result = subprocess.run(args, input=input_data, text=True, capture_output=True)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise InstallError(f"{' '.join(args)} failed: {detail[-1500:]}")
    if show and result.stdout.strip():
        print(result.stdout.strip())
    return result.stdout


def source_files(component: str) -> list[Path]:
    if component == "server":
        roots = (ROOT / "server" / "Dockerfile", ROOT / "server" / "pom.xml",
                 ROOT / "server" / "src", ROOT / "platform-policy", ROOT / "platform-contract",
                 ROOT / ".dockerignore")
    elif component == "admin":
        roots = (ROOT / "admin",)
    else:
        raise ValueError(component)
    files: list[Path] = []
    for root in roots:
        candidates = root.rglob("*") if root.is_dir() else (root,)
        for path in candidates:
            if any(part in {"node_modules", "dist", "target", ".vite", "__pycache__"}
                   for part in path.relative_to(ROOT).parts):
                continue
            if path.is_file() and not path.is_symlink():
                files.append(path)
    if not files:
        raise InstallError(f"No {component} build inputs found")
    return sorted(set(files))


def image_tag(component: str) -> str:
    digest = hashlib.sha256()
    if component == "admin":
        for build_arg in ADMIN_BUILD_ARGS:
            digest.update(build_arg.encode())
            digest.update(b"\0")
    for path in source_files(component):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"local-{digest.hexdigest()[:16]}"


def helm_values() -> list[str]:
    return ["-f", str(HERE / "values.yaml"), "--set-string", f"server.image.tag={image_tag('server')}",
            "--set-string", f"admin.image.tag={image_tag('admin')}"]


def kube(*args: str) -> str:
    return run("kubectl", "--context", CONTEXT, *args)


def kube_json(*args: str) -> dict:
    result = kube(*args, "-o", "json", "--ignore-not-found")
    return json.loads(result) if result.strip() else {}


def release(namespace: str, name: str) -> dict:
    items = json.loads(run("helm", "--kube-context", CONTEXT, "list", "--all", "-n", namespace, "-o", "json"))
    return next((item for item in items if item["name"] == name), {})


def check_tools() -> None:
    for command in (("git", "version"), ("docker", "--version"),
                    ("kubectl", "version", "--client"), ("helm", "version", "--short"),
                    ("openssl", "version"), ("curl", "--version")):
        run(*command)


def check_source() -> None:
    if Path(run("git", "-C", str(ROOT), "rev-parse", "--show-toplevel").strip()).resolve() != ROOT:
        raise InstallError("Not running from the Axiom clone")
    branch = run("git", "-C", str(ROOT), "branch", "--show-current").strip()
    if branch != BRANCH:
        raise InstallError(f"Expected branch {BRANCH}; found {branch or 'detached HEAD'}")
    ignored = (ROOT / ".dockerignore").read_text().splitlines()
    if "deploy/" not in ignored:
        raise InstallError("Docker build context must exclude deploy/ and its plaintext private files")


def check_cluster() -> None:
    if run("kubectl", "config", "current-context").strip() != CONTEXT:
        raise InstallError(f"Current Kubernetes context must be {CONTEXT}")
    nodes = json.loads(kube("get", "nodes", "-o", "json"))
    ready = [node for node in nodes["items"] if any(
        condition["type"] == "Ready" and condition["status"] == "True"
        for condition in node["status"]["conditions"])]
    if not ready:
        raise InstallError("No Ready Kubernetes node")
    if not any(node["metadata"]["name"] == "desktop-worker" for node in ready):
        raise InstallError("Local values select desktop-worker, but that node is not Ready")
    if not run("docker", "info", "--format", "{{.ServerVersion}}").strip():
        raise InstallError("Docker daemon is unavailable")


def check_private(allow_generate: bool) -> None:
    private = HERE / "private"
    if not private.exists() and allow_generate:
        return
    if not private.is_dir() or private.is_symlink():
        raise InstallError("Local private directory is missing or unsafe; use --generate-private only for a new estate")
    for directory in (private, private / "certs", private / "passwords"):
        if not directory.is_dir() or directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) & 0o077:
            raise InstallError(f"Unsafe private directory permissions: {directory}")
    missing = [name for name in PRIVATE_FILES if not (private / name).is_file() or (private / name).is_symlink()]
    if missing:
        raise InstallError("Local private material is incomplete: " + ", ".join(missing))
    for name in PRIVATE_FILES:
        if stat.S_IMODE((private / name).stat().st_mode) & 0o077:
            raise InstallError(f"Unsafe private file permissions: {name}")
    for stem in ("axiom-identity", "axiom-admin"):
        run("openssl", "verify", "-CAfile", str(private / "certs/local-ca.crt"),
            str(private / f"certs/{stem}.crt"))


def check_namespace_safety() -> None:
    expected = {"axiom": {"axiom", "axiom-dependencies"},
                "envoy-gateway-system": {"eg"}, "gateway-demo": {EDGE_RELEASE}}
    for namespace, allowed in expected.items():
        existing = kube_json("get", "namespace", namespace)
        if not existing:
            continue
        names = {item["name"] for item in json.loads(
            run("helm", "--kube-context", CONTEXT, "list", "--all", "-n", namespace, "-o", "json"))}
        if names - allowed:
            raise InstallError(f"Unrelated Helm release in {namespace}; refusing to modify it")
        if namespace == "axiom" and not release(namespace, "axiom-dependencies"):
            claims = kube_json("-n", namespace, "get", "pvc").get("items", [])
            if claims:
                raise InstallError("Unowned Axiom PVCs exist; refuse to guess their credentials or history")
        if namespace in {"axiom", "gateway-demo"}:
            labels = existing["metadata"].get("labels", {})
            for mode in ("enforce", "audit", "warn"):
                if labels.get(f"pod-security.kubernetes.io/{mode}") != "restricted":
                    raise InstallError(f"{namespace} lacks restricted Pod Security {mode} label")
    for namespace, name, charts in (("axiom", "axiom", {"axiom-0.1.3", "axiom-0.1.4"}),
                                     ("axiom", "axiom-dependencies", {"axiom-dependencies-0.1.0"}),
                                     ("envoy-gateway-system", "eg", {"gateway-helm-v1.9.1"}),
                                     ("gateway-demo", EDGE_RELEASE, {"axiom-local-edge-0.1.0"})):
        present = release(namespace, name)
        if present and (present.get("status") != "deployed" or present.get("chart") not in charts):
            raise InstallError(f"{namespace}/{name} is not the expected deployed chart; refusing takeover")


def ensure_namespace(name: str, restricted: bool) -> None:
    if not kube_json("get", "namespace", name):
        kube("create", "namespace", name)
        print(f"Created namespace {name}")
        if restricted:
            kube("label", "namespace", name, *(f"pod-security.kubernetes.io/{mode}=restricted"
                for mode in ("enforce", "audit", "warn")))


def render() -> None:
    run("helm", "lint", str(EDGE_CHART))
    run("helm", "template", EDGE_RELEASE, str(EDGE_CHART), "-n", "gateway-demo")
    for chart, values in (("axiom-dependencies", "dependencies-values.yaml"),
                          ("axiom", "values.yaml")):
        run("helm", "lint", str(ROOT / "deploy/helm" / chart), "-f", str(HERE / values))
        args = helm_values() if chart == "axiom" else ["-f", str(HERE / values)]
        rendered = run("helm", "template", chart, str(ROOT / "deploy/helm" / chart),
                       "-n", "axiom", *args, "--skip-tests")
        if "kind: Deployment" not in rendered and "kind: StatefulSet" not in rendered:
            raise InstallError(f"{chart} rendered no workloads")
    run("helm", "template", "eg", ENVOY_CHART, "--version", ENVOY_VERSION,
        "-n", "envoy-gateway-system", "--include-crds")
    print("Chart lint and offline render: PASS")


def server_dry_run() -> None:
    for chart, args in (("axiom-dependencies", ["-f", str(HERE / "dependencies-values.yaml")]),
                        ("axiom", helm_values())):
        rendered = run("helm", "template", chart, str(ROOT / "deploy/helm" / chart),
                       "-n", "axiom", *args, "--skip-tests")
        run("kubectl", "--context", CONTEXT, "apply", "--dry-run=server", "-f", "-",
            input_data=rendered)
    if not release("envoy-gateway-system", "eg"):
        rendered = run("helm", "template", "eg", ENVOY_CHART, "--version", ENVOY_VERSION,
                       "-n", "envoy-gateway-system", "--include-crds")
        run("kubectl", "--context", CONTEXT, "apply", "--server-side", "--dry-run=server",
            "-f", "-", input_data=rendered)
    print("Kubernetes server-side admission dry-run: PASS")


def helm_install(name: str, namespace: str, chart: str, *args: str, timeout: str) -> None:
    run("helm", "--kube-context", CONTEXT, "upgrade", "--install", name, chart,
        "-n", namespace, *args, "--atomic", "--wait", "--timeout", timeout)
    print(f"Helm release {namespace}/{name}: deployed")


def helm_test(name: str) -> None:
    run("helm", "--kube-context", CONTEXT, "test", name, "-n", "axiom", "--logs")
    print(f"Helm test {name}: PASS")


def check_deployed_images(require_current_source: bool = True) -> None:
    values = json.loads(run("helm", "--kube-context", CONTEXT, "get", "values", "axiom",
                            "-n", "axiom", "-o", "json"))
    for name, component in (("axiom", "server"), ("axiom-admin", "admin")):
        deployment = json.loads(kube("-n", "axiom", "get", "deployment", name, "-o", "json"))
        image = deployment["spec"]["template"]["spec"]["containers"][0]["image"]
        tag = image_tag(component) if require_current_source else values[component]["image"]["tag"]
        wanted = f"axiom-{component}:{tag}"
        if image != wanted:
            raise InstallError(f"Existing {name} image differs from expected release: {image} != {wanted}; backup/review upgrade")


def check_edge_configuration() -> None:
    remaining = kube("create", "--dry-run=client", "--validate=false",
                     "-f", str(HERE / "gateway.yaml"), "-o", "json").strip()
    resources = []
    decoder = json.JSONDecoder()
    while remaining:
        rendered, end = decoder.raw_decode(remaining)
        resources.extend(rendered.get("items", [rendered]))
        remaining = remaining[end:].strip()
    shared = any(item.get("kind") == "EnvoyProxy" and item.get("spec", {}).get("mergeGateways") is True
                 for item in resources)
    if shared and any(item.get("kind") == "Gateway" and
                      item.get("spec", {}).get("infrastructure", {}).get("parametersRef")
                      for item in resources):
        raise InstallError("Shared mode requires removing Gateway infrastructure.parametersRef; "
                           "review that Gateway change before installing")


def check_gateway() -> None:
    gateway_class = json.loads(kube("get", "gatewayclass", "axiom-local-gateway", "-o", "json"))
    if not any(c["type"] == "Accepted" and c["status"] == "True"
               for c in gateway_class["status"].get("conditions", [])):
        raise InstallError("Axiom local GatewayClass is not Accepted")
    if gateway_class["spec"].get("parametersRef") != {
        "group": "gateway.envoyproxy.io", "kind": "EnvoyProxy",
        "name": "axiom-local-proxy", "namespace": "gateway-demo",
    }:
        raise InstallError("Axiom local GatewayClass must reference the shared EnvoyProxy")
    proxy = json.loads(kube("-n", "gateway-demo", "get", "envoyproxy", "axiom-local-proxy", "-o", "json"))
    if proxy["spec"].get("mergeGateways") is not True:
        raise InstallError("Axiom local EnvoyProxy must enable mergeGateways")
    gateway = json.loads(kube("-n", "gateway-demo", "get", "gateway", "axiom-local-edge", "-o", "json"))
    if not any(c["type"] == "Programmed" and c["status"] == "True"
               for c in gateway["status"].get("conditions", [])):
        raise InstallError("Axiom local Gateway is not Programmed")
    routes = json.loads(kube("-n", "gateway-demo", "get", "httproutes", "-o", "json"))["items"]
    expected = {"axiom-admin-http", "axiom-admin-https", "axiom-identity-http", "axiom-identity-https"}
    for route in routes:
        if route["metadata"]["name"] not in expected:
            continue
        conditions = {c["type"]: c["status"] for parent in route.get("status", {}).get("parents", [])
                      for c in parent.get("conditions", [])}
        if conditions.get("Accepted") != "True" or conditions.get("ResolvedRefs") != "True":
            raise InstallError(f"HTTPRoute {route['metadata']['name']} is not ready")
        expected.remove(route["metadata"]["name"])
    if expected:
        raise InstallError("Missing local HTTPRoutes: " + ", ".join(sorted(expected)))
    services = json.loads(kube("-n", "envoy-gateway-system", "get", "services", "-o", "json"))["items"]
    matching = [item for item in services if item["metadata"].get("labels", {}).get(
        "gateway.envoyproxy.io/owning-gatewayclass") == "axiom-local-gateway"]
    if len(matching) != 1 or matching[0]["spec"]["type"] != "LoadBalancer":
        raise InstallError("Expected exactly one LoadBalancer Axiom Envoy data-plane Service")
    if matching[0]["spec"].get("externalTrafficPolicy") != "Cluster":
        raise InstallError("Axiom Envoy LoadBalancer must route traffic to the ready pod from any node")
    if not matching[0].get("status", {}).get("loadBalancer", {}).get("ingress"):
        raise InstallError("Axiom Envoy LoadBalancer has no address")
    if not any(port.get("port") == 443 and port.get("protocol", "TCP") == "TCP"
               for port in matching[0]["spec"].get("ports", [])):
        raise InstallError("Shared Axiom Envoy LoadBalancer must expose HTTPS port 443")


def status() -> None:
    for namespace, name in (("axiom", "axiom-dependencies"), ("axiom", "axiom"),
                            ("envoy-gateway-system", "eg")):
        if release(namespace, name).get("status") != "deployed":
            raise InstallError(f"Helm release {namespace}/{name} is not deployed")
    check_deployed_images(require_current_source=False)
    for name in ("axiom", "axiom-admin", "axiom-cerbos"):
        deployment = json.loads(kube("-n", "axiom", "get", "deployment", name, "-o", "json"))
        if deployment["status"].get("availableReplicas", 0) < 1:
            raise InstallError(f"Deployment axiom/{name} is unavailable")
    for name in ("axiom-postgresql", "axiom-redis"):
        stateful = json.loads(kube("-n", "axiom", "get", "statefulset", name, "-o", "json"))
        if stateful["status"].get("readyReplicas", 0) < 1:
            raise InstallError(f"StatefulSet axiom/{name} is unavailable")
    check_gateway()
    print("Axiom, dependencies, and local Envoy: READY")


def network_canary() -> None:
    if kube_json("-n", "axiom", "get", "pod", "axiom-local-network-canary"):
        raise InstallError("Network canary already exists; refusing to adopt it")
    kube("apply", "-f", str(HERE / "network-canary.yaml"))
    try:
        kube("-n", "axiom", "wait", "--for=jsonpath={.status.phase}=Succeeded",
             "pod/axiom-local-network-canary", "--timeout=90s")
        output = kube("-n", "axiom", "logs", "pod/axiom-local-network-canary")
        if "Redis Service DNS resolved." not in output or "Redis access denied to an unlabeled pod." not in output:
            raise InstallError("Network denial canary did not prove DNS plus Redis isolation")
        print("Network denial canary: PASS")
    finally:
        kube("-n", "axiom", "delete", "pod", "axiom-local-network-canary", "--wait=false")


def install_edge() -> None:
    rendered = run("helm", "template", EDGE_RELEASE, str(EDGE_CHART), "-n", "gateway-demo")
    run("kubectl", "--context", CONTEXT, "apply", "--dry-run=server", "-f", "-", input_data=rendered)
    existing_release = release("gateway-demo", EDGE_RELEASE)
    if existing_release or not kube_json("get", "gatewayclass", "axiom-local-gateway"):
        helm_install(EDGE_RELEASE, "gateway-demo", str(EDGE_CHART), timeout="5m")
    else:
        # Keep ownership of older manifest installations; never force Helm adoption.
        run("kubectl", "--context", CONTEXT, "apply", "-f", "-", input_data=rendered)
        print("Existing manifest edge updated from the Helm chart; ownership retained")


def check_https() -> None:
    args = ("curl", "--noproxy", "*", "--fail", "--silent", "--show-error",
            "--max-time", "10", "--retry", "6", "--retry-connrefused", "--retry-delay", "2",
            "--retry-max-time", "30", "--cacert", str(HERE / "private/certs/local-ca.crt"))
    issuer = "https://identity.meridian.com"
    discovery = json.loads(run(*args, issuer + "/.well-known/openid-configuration"))
    if discovery.get("issuer") != issuer:
        raise InstallError("HTTPS discovery returned the wrong Axiom issuer")
    run(*args, "--output", "/dev/null", issuer + "/actuator/health/readiness")
    run(*args, "--output", "/dev/null", "https://identity-admin.meridian.com/")
    print("Laptop HTTPS discovery, readiness and Admin with existing CA: PASS")


def install(allow_envoy: bool, generate_private: bool) -> None:
    check_tools()
    check_source()
    check_cluster()
    check_edge_configuration()
    check_private(generate_private)
    check_namespace_safety()
    if not (HERE / "private").exists() and any(
        kube_json("get", "namespace", name) for name in ("axiom", "gateway-demo")
    ):
        raise InstallError("Private files are missing but an Axiom namespace exists; do not generate new credentials")
    render()
    if not release("envoy-gateway-system", "eg") and not allow_envoy:
        raise InstallError("Installing Envoy creates cluster-scoped CRDs/RBAC; rerun with --allow-envoy-install after review")
    if release("axiom", "axiom"):
        check_deployed_images()  # Do not silently upgrade a database-backed release.
    for component in ("server", "admin"):
        run("docker", "build", "-f", str(ROOT / component / "Dockerfile"),
            "-t", f"axiom-{component}:{image_tag(component)}",
            *(sum((["--build-arg", value] for value in ADMIN_BUILD_ARGS), [])
              if component == "admin" else []),
            str(ROOT))
        print(f"Built axiom-{component}:{image_tag(component)}")
    ensure_namespace("axiom", restricted=True)
    ensure_namespace("gateway-demo", restricted=True)
    ensure_namespace("envoy-gateway-system", restricted=False)
    if not (HERE / "private").exists():
        run(sys.executable, str(HERE / "prepare-private.py"), "generate")
    run(sys.executable, str(HERE / "prepare-private.py"), "ensure")
    server_dry_run()
    if not release("axiom", "axiom-dependencies"):
        helm_install("axiom-dependencies", "axiom", str(ROOT / "deploy/helm/axiom-dependencies"),
                     "-f", str(HERE / "dependencies-values.yaml"), timeout="10m")
    helm_test("axiom-dependencies")
    if not release("axiom", "axiom"):
        helm_install("axiom", "axiom", str(ROOT / "deploy/helm/axiom"),
                     *helm_values(), timeout="15m")
    helm_test("axiom")
    if not release("envoy-gateway-system", "eg"):
        helm_install("eg", "envoy-gateway-system", ENVOY_CHART,
                     "--version", ENVOY_VERSION, timeout="5m")
    install_edge()
    kube("wait", "--for=condition=Accepted", "gatewayclass/axiom-local-gateway", "--timeout=3m")
    kube("-n", "gateway-demo", "wait", "--for=condition=Programmed",
         "gateway/axiom-local-edge", "--timeout=3m")
    status()
    network_canary()
    check_https()
    print("Local cluster installation passed, including HTTPS port 443.")


def plan() -> None:
    print("profile: disposable Docker Desktop local edge (not production)")
    print(f"required context: {CONTEXT}; required branch: {BRANCH}")
    print(f"server image: axiom-server:{image_tag('server')}")
    print(f"admin image: axiom-admin:{image_tag('admin')}")
    print("order: validate -> render -> build -> namespaces/Secrets -> dependencies -> Axiom -> Envoy -> routes -> tests")
    print("cluster-scoped Envoy install needs --allow-envoy-install; no data or namespace teardown is performed")
    print("browser access uses the Envoy LoadBalancer on HTTPS port 443; no port-forward")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "validate", "dry-run", "install", "status"))
    parser.add_argument("--allow-envoy-install", action="store_true")
    parser.add_argument("--generate-private", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            check_source()
            plan()
        elif args.command == "validate":
            check_tools()
            check_source()
            check_cluster()
            check_private(args.generate_private)
            check_namespace_safety()
            print("Axiom local preflight: PASS")
        elif args.command == "dry-run":
            check_source()
            render()
        elif args.command == "install":
            install(args.allow_envoy_install, args.generate_private)
        elif args.command == "status":
            check_cluster()
            status()
    except (InstallError, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
