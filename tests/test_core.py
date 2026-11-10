import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certwatch.core import CertificateError, inspect, load_certificate, report, verify_chain


def make_certificate(now, key_size=2048, days=60, hostname="example.invalid"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, cert.public_bytes(serialization.Encoding.PEM)


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_pem_der_and_metadata(self):
        cert, pem = make_certificate(self.now)
        self.assertEqual(load_certificate(pem, ".pem").serial_number, cert.serial_number)
        der = cert.public_bytes(serialization.Encoding.DER)
        self.assertEqual(load_certificate(der, ".der").serial_number, cert.serial_number)
        item = inspect(cert, pem, self.now, 30)
        self.assertEqual(item["validity_state"], "validity_window_current")
        self.assertEqual(item["dns_sans"], ["example.invalid"])

    def test_expiration_and_weak_key(self):
        cert, pem = make_certificate(self.now, key_size=1024, days=5)
        item = inspect(cert, pem, self.now, 30)
        self.assertEqual(item["validity_state"], "renewal_due")
        self.assertTrue(item["weak_key_indicator"])
        self.assertEqual(inspect(cert, pem, self.now + timedelta(days=6), 30)["validity_state"], "expired")

    def test_private_key_and_multiple_pem_rejected(self):
        _, pem = make_certificate(self.now)
        with self.assertRaises(CertificateError):
            load_certificate(pem + b"-----BEGIN PRIVATE KEY-----\nTEST\n", ".pem")
        with self.assertRaises(CertificateError):
            load_certificate(pem + pem, ".pem")

    def test_supplied_root_chain(self):
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test root")])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.invalid")])
        root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(self.now - timedelta(days=1))
                .not_valid_after(self.now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False,
                                             key_agreement=False, key_cert_sign=True, crl_sign=True,
                                             encipher_only=False, decipher_only=False), critical=True)
                .sign(root_key, hashes.SHA256()))
        cert = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(root_name)
                .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(self.now - timedelta(days=1))
                .not_valid_after(self.now + timedelta(days=60))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.invalid")]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(root_key, hashes.SHA256()))
        result = verify_chain(cert, [], [root], "example.invalid", self.now)
        self.assertEqual(result["trust_state"], "verified_against_supplied_roots", result)
        wrong = verify_chain(cert, [], [root], "other.invalid", self.now)
        self.assertEqual(wrong["trust_state"], "verification_failed")

    def test_report_public_key_reuse(self):
        cert, pem = make_certificate(self.now)
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a.pem", Path(tmp) / "b.pem"
            a.write_bytes(pem)
            b.write_bytes(pem)
            result = report([a, b], self.now, 30)
        self.assertEqual(len(result["certificates"]), 2)
        self.assertEqual(result["public_key_reuse"], [])


if __name__ == "__main__":
    unittest.main()
