# Lab test CA — NOT for production

`lab_root.pem` is a **lab-only test CA certificate** (self-signed, CN=CipherPost Lab Trusted Root).

- Contains **no private key** (certificate only).
- Used by `scripts/traffic_generator.py` and `tests/fixtures/` to create
  deterministic test chains.
- **Must never be used as a trust anchor in production.**
  Production must set `CIPHERPOST_TRUSTED_CA_BUNDLE_PATH` to the organization's
  real trust bundle (system CA store or private PKI root).
