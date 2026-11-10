# CertWatch validation report

Date: 2026-11-09. Tests generated ephemeral, non-production certificates in memory. Private keys were neither printed nor written to the repository.

| Check | Actual result |
| --- | --- |
| Python compilation | Passed |
| `python3 -m unittest discover -s tests -v` | 5 passed, 0 failed, 0 skipped after fixing two test-discovered issues |
| PEM/DER parsing, SAN, expiration, weak RSA, fingerprint, explicit-root trust validation | Tested with ephemeral certificates |
| Private-key and concatenated-PEM rejection | Tested |
| Live TLS, CT feed, renewal service | Not implemented or verified |
| Ruff/pytest, Docker, dashboard | Unavailable or not applicable to offline milestone |

Two initial failures were fixed: the PEM matcher accepted concatenated certificates, and a chain test incorrectly used a CA as the server leaf. The corrected test uses a signed server leaf, explicit root, and hostname. No production PKI integration was tested.
