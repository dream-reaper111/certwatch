# Security model

Use only public certificates obtained with authorization. CertWatch rejects input containing private-key PEM markers and never serializes a private key. `.gitignore` excludes common private-key extensions but cannot replace a pre-publication review. Certificate subject and SAN values can identify organizations or internal hosts; protect reports accordingly.

Parsing untrusted X.509 data depends on `cryptography`. Use a maintained version and a resource-limited analysis environment. The CLI does not perform network traffic or change a certificate store. Optional trust results are scoped to user-supplied roots and hostname. No certificate is described as trusted by a platform default.
