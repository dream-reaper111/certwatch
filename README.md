# CertWatch

CertWatch's first milestone is an offline X.509 certificate inventory and review CLI. It imports one certificate per PEM or DER file, extracts validity windows, SANs, signature OIDs, public-key algorithms and sizes, SHA-256 fingerprints, and public-key reuse metadata. It rejects private-key material. Optional chain verification uses **only explicitly supplied trust roots and expected hostname**. It never contacts a TLS endpoint or certificate transparency service.

## Run

Python 3.12+ and `cryptography>=42` are required. The currently installed 49.0.0 library passed the unit tests.

```bash
PYTHONPATH=. python3.12 -m certwatch.cli /path/to/authorized-leaf.pem > report.json
PYTHONPATH=. python3.12 -m certwatch.cli --root /path/to/approved-root.pem --hostname service.example.org /path/to/authorized-leaf.pem > report.json
python3.12 -m unittest discover -s tests -v
```

The report labels certificates as expired, not yet valid, renewal due, or currently within their validity window. This is certificate metadata review, not a claim about a live service's TLS configuration. Trust-chain verification uses `cryptography`'s [X.509 verification API](https://cryptography.io/en/stable/x509/verification/) and supplied roots; without them it reports `not_checked`. Key-size indicators follow explicit local thresholds (RSA/DSA below 2048 bits, EC below 224 bits) and are review cues, not a complete cryptographic policy.

## Limits

One input file is capped at 1 MiB, and one report at 1,000 certificates. Multi-certificate PEM chains must be split into individual files. There is no online TLS inspection, CT enrichment, renewal scheduler, database, dashboard, or system trust-store assumption. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md). Next: test against authorized certificate inventories and add policy profiles for different PKI contexts before adding monitoring services.
