"""Offline certificate-shape checks for the disposable local edge profile."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("prepare-private.py")


class LocalTlsTest(unittest.TestCase):
    def test_ca_and_server_leaf_are_separate_and_verifiable(self) -> None:
        spec = importlib.util.spec_from_file_location("axiom_prepare_private", SCRIPT)
        assert spec is not None and spec.loader is not None
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory(prefix="axiom-local-tls-") as directory:
            helper.CERTS = Path(directory)
            helper.generate_local_ca()
            helper.generate_shared_tls()
            self.assertEqual((helper.CERTS / "axiom-identity.crt").read_bytes(),
                             (helper.CERTS / "axiom-admin.crt").read_bytes())
            self.assertEqual((helper.CERTS / "axiom-identity.key").read_bytes(),
                             (helper.CERTS / "axiom-admin.key").read_bytes())
            for stem in ("axiom-identity", "axiom-admin"):
                cert = helper.CERTS / f"{stem}.crt"
                ca = helper.CERTS / "local-ca.crt"
                subprocess.run(["openssl", "verify", "-CAfile", str(ca), str(cert)],
                               check=True, capture_output=True)
                output = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", "-text"],
                                        check=True, capture_output=True, text=True).stdout
                self.assertIn("CA:FALSE", output)
                self.assertIn("TLS Web Server Authentication", output)
                for hostname in helper.LOCAL_CERT_HOSTNAMES:
                    self.assertIn(f"DNS:{hostname}", output)
                self.assertIn("Digital Signature", output)
                self.assertNotIn("CA:TRUE", output)

    def test_tls_renewal_preserves_signing_key_password_and_old_leaf(self) -> None:
        spec = importlib.util.spec_from_file_location("axiom_prepare_private_renewal", SCRIPT)
        assert spec is not None and spec.loader is not None
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory(prefix="axiom-local-tls-renewal-") as directory:
            helper.PRIVATE = Path(directory)
            helper.CERTS = helper.PRIVATE / "certs"
            helper.PASSWORDS = helper.PRIVATE / "passwords"
            helper.CERTS.mkdir()
            helper.PASSWORDS.mkdir()
            helper.generate_local_ca()
            old_ca = (helper.CERTS / "local-ca.crt").read_bytes()
            (helper.CERTS / "axiom-identity.crt").write_text("prior leaf")
            (helper.CERTS / "signing-key.json").write_text("unchanged signer")
            (helper.PASSWORDS / "axiom-admin-password").write_text("unchanged password")
            helper.renew_tls()
            backups = list(helper.CERTS.glob("previous-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual((backups[0] / "axiom-identity.crt").read_text(), "prior leaf")
            self.assertEqual((helper.CERTS / "signing-key.json").read_text(), "unchanged signer")
            self.assertEqual((helper.PASSWORDS / "axiom-admin-password").read_text(), "unchanged password")
            self.assertNotEqual((helper.CERTS / "local-ca.crt").read_bytes(), old_ca)
            helper.verify_tls()


if __name__ == "__main__":
    unittest.main()
