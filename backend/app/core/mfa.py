"""TOTP MFA for local accounts (Phase 3 Task 1). No new dependencies.

- RFC 6238 TOTP (SHA1, 30 s step, 6 digits) with stdlib hmac/hashlib only.
- Secrets encrypted at rest (AES-GCM via `cryptography`, key derived from
  CIPHERPOST_JWT_SECRET). Fail closed: undecryptable secrets reject.
- Recovery codes: 10 single-use codes, SHA-256 hashed (like passwords).
- Brute-force protection: 5 failures / 5 min per user lock the MFA step
  (in-memory + best-effort Redis, same pattern as login lockout).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

STEP = 30
DIGITS = 6
WINDOW_STEPS = 1  # accept +-1 step for clock skew
_MFA_MAX_ATTEMPTS = 5
_MFA_WINDOW_SECONDS = 300

_mem_mfa_failures: dict[str, list[float]] = {}


def random_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_uri(secret: str, account: str, issuer: str) -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}"
            f"?secret={secret}&issuer={quote(issuer)}&digits=6&period=30")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** DIGITS)).zfill(DIGITS)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at if at is not None else time.time()) // STEP))


def verify_code(secret_b32: str, code: str, at: float | None = None) -> bool:
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return False
    base = int((at if at is not None else time.time()) // STEP)
    for delta in range(-WINDOW_STEPS, WINDOW_STEPS + 1):
        if hmac.compare_digest(_hotp(secret_b32, base + delta), code):
            return True
    return False


# --------------------------------------------------------------------------
# Secret encryption at rest (AES-GCM, key from JWT_SECRET; fail closed)
# --------------------------------------------------------------------------

def _enc_key() -> bytes:
    from app.core import config as _cfg
    secret = (_cfg.settings.JWT_SECRET or "").encode()
    if len(secret) < 32:
        raise ValueError("mfa-error: JWT secret too weak to wrap MFA secrets")
    return hashlib.pbkdf2_hmac("sha256", secret, b"cipherpost-mfa-v1", 100_000, dklen=32)


def encrypt_secret(plain_b32: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_enc_key()).encrypt(nonce, plain_b32.encode(), None)
    return f"v1${nonce.hex()}${ct.hex()}"


def decrypt_secret(stored: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        ver, nonce_hex, ct_hex = stored.split("$")
        if ver != "v1":
            raise ValueError("unknown version")
        pt = AESGCM(_enc_key()).decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)
        return pt.decode()
    except Exception as e:
        raise ValueError(f"mfa-error: cannot unwrap secret ({e})")


# --------------------------------------------------------------------------
# Recovery codes (hashed, single-use)
# --------------------------------------------------------------------------

def new_recovery_codes(n: int = 10) -> list[str]:
    codes = []
    for _ in range(n):
        codes.append(secrets.token_hex(3) + "-" + secrets.token_hex(3))
    return codes


def hash_recovery_code(code: str) -> str:
    norm = code.strip().lower().replace(" ", "")
    return hashlib.sha256(norm.encode()).hexdigest()


def consume_recovery_code(stored_hashes: list[str], code: str) -> list[str] | None:
    """Return the remaining hashes if code matches (single-use), else None."""
    want = hash_recovery_code(code)
    for i, h in enumerate(stored_hashes or []):
        if hmac.compare_digest(h, want):
            return [x for j, x in enumerate(stored_hashes) if j != i]
    return None


# --------------------------------------------------------------------------
# Brute-force protection on the MFA step
# --------------------------------------------------------------------------

def _mfa_redis():
    try:
        import redis as _redis
        from app.core import config as _cfg
        return _redis.Redis.from_url(_cfg.settings.REDIS_URL, decode_responses=True,
                                     socket_connect_timeout=1, socket_timeout=1)
    except Exception:
        return None


def mfa_locked(user_key: str) -> bool:
    now = time.time()
    r = _mfa_redis()
    if r is not None:
        try:
            return bool(r.get(user_key + ":mfa-lock"))
        except Exception:
            pass
    hits = [t for t in _mem_mfa_failures.get(user_key, []) if now - t < _MFA_WINDOW_SECONDS]
    return len(hits) >= _MFA_MAX_ATTEMPTS


def record_mfa_failure(user_key: str) -> None:
    now = time.time()
    r = _mfa_redis()
    if r is not None:
        try:
            n = r.incr(user_key + ":mfa")
            if n == 1:
                r.expire(user_key + ":mfa", _MFA_WINDOW_SECONDS)
            if n >= _MFA_MAX_ATTEMPTS:
                r.setex(user_key + ":mfa-lock", _MFA_WINDOW_SECONDS, "1")
            return
        except Exception:
            pass
    hits = [t for t in _mem_mfa_failures.get(user_key, []) if now - t < _MFA_WINDOW_SECONDS]
    hits.append(now)
    _mem_mfa_failures[user_key] = hits


def record_mfa_success(user_key: str) -> None:
    r = _mfa_redis()
    if r is not None:
        try:
            r.delete(user_key + ":mfa", user_key + ":mfa-lock")
            return
        except Exception:
            pass
    _mem_mfa_failures.pop(user_key, None)


def reset_mfa_state() -> None:
    """Test-only: clear in-memory buckets and best-effort Redis keys."""
    _mem_mfa_failures.clear()
    r = _mfa_redis()
    if r is not None:
        try:
            for k in list(r.keys("*:mfa")) + list(r.keys("*:mfa-lock")):
                r.delete(k)
        except Exception:
            pass
