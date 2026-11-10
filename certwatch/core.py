"""Read-only PEM/DER certificate analysis; private-key material is rejected."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.verification import DNSName, PolicyBuilder, Store, VerificationError

MAX_CERT = 1024 * 1024
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*")


class CertificateError(ValueError):
    pass


def load_certificate(raw: bytes, suffix: str) -> x509.Certificate:
    if not 0 < len(raw) <= MAX_CERT:
        raise CertificateError("certificate input must be 1 to 1 MiB")
    if b"PRIVATE KEY" in raw.upper():
        raise CertificateError("private key material is not accepted")
    try:
        if suffix.lower() == ".pem":
            if not PEM_CERT.fullmatch(raw):
                raise CertificateError("PEM input must contain exactly one certificate")
            return x509.load_pem_x509_certificate(raw)
        if suffix.lower() in {".der", ".cer", ".crt"}:
            return x509.load_der_x509_certificate(raw)
    except ValueError as exc:
        raise CertificateError("invalid X.509 certificate") from exc
    raise CertificateError("supported extensions: .pem, .der, .cer, .crt")


def load_file(path: Path) -> tuple[x509.Certificate, bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CERT:
        raise CertificateError("certificate must be a regular file of at most 1 MiB")
    raw = path.read_bytes()
    return load_certificate(raw, path.suffix), raw


def inspect(cert: x509.Certificate, raw: bytes, now: datetime, renewal_days: int) -> dict:
    if now.tzinfo is None or not 1 <= renewal_days <= 365:
        raise CertificateError("timezone-aware now and 1-365 renewal days required")
    now = now.astimezone(timezone.utc)
    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    if end < now:
        state = "expired"
    elif start > now:
        state = "not_yet_valid"
    elif (end - now).total_seconds() <= renewal_days * 86400:
        state = "renewal_due"
    else:
        state = "validity_window_current"
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = [str(value) for value in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_names = [], []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algorithm, size = "RSA", key.key_size
        weak = size < 2048
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algorithm, size = "EC", key.key_size
        weak = size < 224
    elif isinstance(key, dsa.DSAPublicKey):
        algorithm, size = "DSA", key.key_size
        weak = size < 2048
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        algorithm, size, weak = type(key).__name__, None, False
    else:
        algorithm, size, weak = type(key).__name__, None, None
    public_der = key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"certificate_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "input_sha256": hashlib.sha256(raw).hexdigest(),
            "public_key_sha256": hashlib.sha256(public_der).hexdigest(),
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial_hex": format(cert.serial_number, "x"),
            "not_valid_before_utc": start.isoformat(), "not_valid_after_utc": end.isoformat(),
            "validity_state": state, "dns_sans": dns_names, "ip_sans": ip_names,
            "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
            "public_key_algorithm": algorithm, "public_key_bits": size,
            "weak_key_indicator": weak,
            "trust_state": "not_checked",
            "interpretation": "certificate metadata only; no live TLS endpoint inspected"}


def verify_chain(leaf: x509.Certificate, intermediates: list[x509.Certificate],
                 roots: list[x509.Certificate], hostname: str, now: datetime) -> dict:
    if not roots or not hostname or now.tzinfo is None:
        raise CertificateError("explicit trust roots, hostname and aware time required")
    try:
        verifier = PolicyBuilder().store(Store(roots)).time(now.astimezone(timezone.utc)).build_server_verifier(DNSName(hostname))
        chain = verifier.verify(leaf, intermediates)
    except (VerificationError, ValueError) as exc:
        return {"trust_state": "verification_failed", "reason": str(exc)[:200],
                "trusted_chain_length": None}
    return {"trust_state": "verified_against_supplied_roots", "trusted_chain_length": len(chain),
            "hostname": hostname}


def report(paths: list[Path], now: datetime, renewal_days: int,
           roots: list[Path] | None = None, hostname: str | None = None) -> dict:
    if not 1 <= len(paths) <= 1000:
        raise CertificateError("1-1000 certificate paths required")
    root_certs = [load_file(path)[0] for path in (roots or [])]
    parsed = [load_file(path) for path in paths]
    items = []
    for path, (cert, raw) in zip(paths, parsed):
        result = inspect(cert, raw, now, renewal_days)
        result["source_path"] = str(path)
        if roots is not None and hostname:
            result.update(verify_chain(cert, [item[0] for item in parsed if item[0] != cert],
                                       root_certs, hostname, now))
        items.append(result)
    reuse = {}
    for item in items:
        reuse.setdefault(item["public_key_sha256"], []).append(item["certificate_sha256"])
    return {"schema_version": 1, "analyzed_at_utc": now.astimezone(timezone.utc).isoformat(),
            "certificates": items,
            "public_key_reuse": [{"public_key_sha256": digest, "certificate_sha256s": ids}
                                 for digest, ids in reuse.items() if len(set(ids)) > 1],
            "trust_note": "trust verification uses supplied roots and hostname only; no system trust inferred"}
