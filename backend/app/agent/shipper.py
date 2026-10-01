"""HTTPS shipper to /api/v1/ingest/sessions (Phase 3 Task 3).

Stdlib urllib only (no new deps): gzipped batches, retry with exponential
backoff + jitter, 429 backpressure honored (Retry-After), TLS verification
with optional SHA-256 SPKI pinning. A 401 (revoked/rotated token) stops the
shipper loudly instead of burning through the queue.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import random
import ssl
import time
import urllib.request

log = logging.getLogger("cipherpost.agent.shipper")


class RevokedToken(Exception):
    pass


def _spki_pin(cert_der: bytes) -> str:
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import serialization as _ser
    cert = _x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


class Shipper:
    def __init__(self, base_url: str, token: str, ca_bundle: str | None = None,
                 pin: str | None = None, timeout: float = 15.0,
                 max_retries: int = 6):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.ca_bundle = ca_bundle
        self.pin = (pin or "").lower().replace(":", "")
        self.timeout = timeout
        self.max_retries = max_retries
        self.revoked = False

    def _context(self) -> ssl.SSLContext:
        if self.ca_bundle:
            return ssl.create_default_context(cafile=self.ca_bundle)
        return ssl.create_default_context()

    def _check_pin(self, resp) -> None:
        if not self.pin:
            return
        try:
            der = resp.fp.raw._sock.getpeercert(binary_form=True)
            if _spki_pin(der) != self.pin:
                raise ValueError("TLS pin mismatch")
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"pin check unavailable: {e}")

    def send_batch(self, sessions: list[dict]) -> dict:
        """POST one batch; returns server summary. Raises on outage."""
        if self.revoked:
            raise RevokedToken("agent token revoked; rotate and restart")
        body = gzip.compress(json.dumps({"sessions": sessions}).encode())
        delay = 1.0
        for attempt in range(max(1, self.max_retries)):
            req = urllib.request.Request(
                self.base_url + "/api/v1/ingest/sessions", data=body,
                method="POST",
                headers={"Content-Type": "application/json",
                         "Content-Encoding": "gzip",
                         "X-Agent-Token": self.token})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout,
                                            context=self._context()) as r:
                    self._check_pin(r)
                    return json.loads(r.read() or b"{}")
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    self.revoked = True
                    log.error("ingest rejected (401): token revoked or rotated; "
                              "stopping shipper, queue retained on disk")
                    raise RevokedToken("ingest 401: rotate the agent token")
                if e.code == 429:
                    wait = float(e.headers.get("Retry-After", "5") or 5)
                    log.info("server backpressure (429), waiting %.0fs", wait)
                    time.sleep(wait)
                    continue
                if 400 <= e.code < 500:
                    raise ValueError(f"ingest rejected: HTTP {e.code}")
                log.debug("ingest attempt %d failed: HTTP %s", attempt + 1, e.code)
            except RevokedToken:
                raise
            except ValueError:
                raise
            except Exception as e:
                log.debug("ingest attempt %d failed: %s", attempt + 1, e)
            time.sleep(delay + random.uniform(0, delay * 0.25))
            delay = min(60.0, delay * 2)
        raise ConnectionError("ingest unavailable after retries")
