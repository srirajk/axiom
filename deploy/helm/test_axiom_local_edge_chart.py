"""Offline contract for the first-install shared Envoy Helm chart."""
from pathlib import Path
import subprocess
import unittest

import yaml

HERE = Path(__file__).resolve().parent


class SharedEdgeChartTest(unittest.TestCase):
    def test_first_install_and_manifest_have_identical_shared_edge_contract(self):
        rendered = subprocess.check_output([
            "helm", "template", "axiom-local-edge", str(HERE / "axiom-local-edge"),
            "-n", "gateway-demo"], text=True)
        documents = [d for d in yaml.safe_load_all(rendered) if d]
        manifest = [d for d in yaml.safe_load_all((HERE.parent / "axiom-local-edge/gateway.yaml").read_text()) if d]
        key = lambda d: (d["kind"], d["metadata"].get("namespace", ""), d["metadata"]["name"])
        self.assertEqual(sorted(documents, key=key), sorted(manifest, key=key))
        by_kind = {d["kind"]: d for d in documents}
        self.assertTrue(by_kind["EnvoyProxy"]["spec"]["mergeGateways"])
        self.assertEqual(by_kind["GatewayClass"]["spec"]["parametersRef"], {
            "group": "gateway.envoyproxy.io", "kind": "EnvoyProxy",
            "name": "axiom-local-proxy", "namespace": "gateway-demo"})
        gateway = by_kind["Gateway"]["spec"]
        self.assertNotIn("infrastructure", gateway)
        self.assertEqual(gateway["gatewayClassName"], "axiom-local-gateway")
        self.assertEqual({l["hostname"] for l in gateway["listeners"]}, {
            "identity.meridian.com", "identity-admin.meridian.com"})
        self.assertEqual({l["tls"]["certificateRefs"][0]["name"] for l in gateway["listeners"] if "tls" in l}, {
            "axiom-identity-tls", "axiom-admin-tls"})
        self.assertEqual(sum(d["kind"] == "HTTPRoute" for d in documents), 4)
        self.assertFalse(any(d["kind"] in {"Secret", "Deployment", "StatefulSet"} for d in documents))


if __name__ == "__main__":
    unittest.main()
