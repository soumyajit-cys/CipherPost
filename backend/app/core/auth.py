"""
Track 1: Authentication, RBAC, API keys.

Design notes:
- JWT is HS256 via PyJWT (pinned algorithm, exp validated, alg=none rejected);
  passwords use PBKDF2-HMAC-SHA256 (200k iterations, per-user 16-byte salt).
- Two credential kinds: user login sessions (short-lived JWT) and long-lived
  API keys (`cp_<hex>`, SHA-256 hash stored, prefix indexed) for SIEM/scripts.
- Roles: admin (full + config/user mgmt), analyst (view + upload), auditor
  (read-only). Role hierarchy enforced in `require_roles`.
- Tenancy: every User/ApiKey/Job/Session carries org_id. Queries filter by
  the caller's org. Single-org deployments just use the seeded "default" org;
  the columns make true multi-tenancy a policy change, not a migration.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import config as _configmod
from app.core.database import get_db

# --------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256, stdlib)
# --------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2-sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, dk_hex = stored.split("$")
        if algo != "pbkdf2-sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# --------------------------------------------------------------------------
# HS256 JWT via PyJWT (pinned alg, exp validated, alg=none rejected)
# --------------------------------------------------------------------------

_JWT_ALG = "HS256"


def _jwt_secret_str() -> str:
    raw = _jwt_secret()
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="surrogateescape")
    return raw


def _jwt_secret() -> bytes:
    from app.core import config as _cfgmod
    s = _cfgmod.settings
    env = (getattr(s, "ENV", "production") or "production").strip().lower()
    secret = getattr(s, "JWT_SECRET", "") or ""
    if env == "dev":
        # Dev only: ephemeral per-process secret + loud warning. Never use a
        # hardcoded constant that an attacker could read from the public repo.
        global _DEV_EPHEMERAL_SECRET
        try:
            _DEV_EPHEMERAL_SECRET
        except NameError:
            import logging as _logging
            _DEV_EPHEMERAL_SECRET = secrets.token_bytes(32)
            _logging.getLogger("cipherpost.auth").warning(
                "CIPHERPOST_ENV=dev: using ephemeral random JWT secret "
                "(logins invalid after restart). Set CIPHERPOST_JWT_SECRET "
                "for stable sessions; never use dev mode in production."
            )
        return _DEV_EPHEMERAL_SECRET
    # Production: refuse weak secrets (defence in depth; startup also checks).
    try:
        _cfgmod.validate_startup_secrets(s)
    except RuntimeError:
        # Re-raise with context pointing at JWT specifically if that is the
        # cause; otherwise propagate the full production refusal.
        raise
    return secret.encode()


def create_access_token(sub: str, org_id: str, role: str,
                        expires_in: int | None = None,
                        extra: dict | None = None,
                        session_version: int = 1) -> str:
    import jwt as _pyjwt
    from app.core import config as _cfgmod2
    if expires_in is None:
        expires_in = int(getattr(_cfgmod2.settings, "JWT_EXPIRY_SECONDS", 86400))
    now = int(time.time())
    payload = {
        "sub": sub, "org": org_id, "role": role,
        "iat": now, "exp": now + expires_in,
        "jti": secrets.token_hex(8), "sv": int(session_version),
    }
    if extra:
        payload.update(extra)
    return _pyjwt.encode(payload, _jwt_secret_str(), algorithm=_JWT_ALG)


def decode_token(token: str) -> dict:
    import jwt as _pyjwt
    try:
        claims = _pyjwt.decode(token, _jwt_secret_str(), algorithms=[_JWT_ALG],
                               options={"require": ["exp", "iat"]})
    except _pyjwt.ExpiredSignatureError as e:
        raise ValueError(f"invalid token: expired ({e})")
    except _pyjwt.InvalidAlgorithmError as e:
        raise ValueError(f"invalid token: bad alg ({e})")
    except _pyjwt.InvalidTokenError as e:
        raise ValueError(f"invalid token: {e}")
    except Exception as e:
        raise ValueError(f"invalid token: {e}")
    return claims


# --------------------------------------------------------------------------
# Login rate limiting / temporary lockout (Redis-backed, in-memory fallback)
# --------------------------------------------------------------------------

_LOGIN_MAX_ATTEMPTS = 5        # failures before account lock
_LOGIN_WINDOW_SECONDS = 300    # sliding window for counting failures
_LOGIN_LOCK_SECONDS = 900      # lockout duration after threshold
_LOGIN_IP_MAX_ATTEMPTS = 20    # per-IP threshold (same window)

_mem_failures: dict[str, list[float]] = {}
_mem_locks: dict[str, float] = {}


def _login_redis():
    try:
        import redis as _redis
        from app.core import config as _cfg
        return _redis.Redis.from_url(_cfg.settings.REDIS_URL, decode_responses=True,
                                     socket_connect_timeout=1, socket_timeout=1)
    except Exception:
        return None


def _mem_prune(key: str, now: float) -> list[float]:
    hits = [t for t in _mem_failures.get(key, []) if now - t < _LOGIN_WINDOW_SECONDS]
    _mem_failures[key] = hits
    return hits


def is_login_locked(account_key: str, ip_key: str) -> bool:
    now = time.time()
    # Redis path (best effort)
    r = _login_redis()
    if r is not None:
        try:
            for k in (account_key, ip_key):
                if r.get(k + ":lock"):
                    return True
            return False
        except Exception:
            pass  # fall through to memory
    for k in (account_key, ip_key):
        until = _mem_locks.get(k, 0)
        if until and now < until:
            return True
    return False


def record_login_failure(account_key: str, ip_key: str) -> None:
    now = time.time()
    r = _login_redis()
    if r is not None:
        try:
            for k, limit in ((account_key, _LOGIN_MAX_ATTEMPTS),
                             (ip_key, _LOGIN_IP_MAX_ATTEMPTS)):
                n = r.incr(k)
                if n == 1:
                    r.expire(k, _LOGIN_WINDOW_SECONDS)
                if n >= limit:
                    r.setex(k + ":lock", _LOGIN_LOCK_SECONDS, "1")
            return
        except Exception:
            pass
    for k, limit in ((account_key, _LOGIN_MAX_ATTEMPTS),
                     (ip_key, _LOGIN_IP_MAX_ATTEMPTS)):
        hits = _mem_prune(k, now)
        hits.append(now)
        if len(hits) >= limit:
            _mem_locks[k] = now + _LOGIN_LOCK_SECONDS


def record_login_success(account_key: str, ip_key: str) -> None:
    r = _login_redis()
    if r is not None:
        try:
            r.delete(account_key, ip_key)
            return
        except Exception:
            pass
    _mem_failures.pop(account_key, None)
    # NOTE: do not clear IP bucket on success (prevents credential-spray reset).


def _reset_login_state() -> None:
    """Test-only: clear in-memory buckets and best-effort Redis keys."""
    _mem_failures.clear()
    _mem_locks.clear()
    r = _login_redis()
    if r is not None:
        try:
            for k in r.keys("login:*"):
                r.delete(k)
        except Exception:
            pass


# --------------------------------------------------------------------------
# Session revocation: jti denylist + per-user session version.
# Redis-backed with bounded in-memory fallback (mirrors SSE tickets):
# revocation is enforced whenever the entry is visible; Redis outage only
# loses cross-process propagation, which is logged loudly.
# --------------------------------------------------------------------------

_revoked_jti: set[str] = set()
_revocation_warned = False


def _revocation_redis():
    try:
        import redis as _redis
        from app.core import config as _cfg
        return _redis.Redis.from_url(_cfg.settings.REDIS_URL, decode_responses=True,
                                     socket_connect_timeout=1, socket_timeout=1)
    except Exception:
        return None


def revoke_token(jti: str, ttl_seconds: int = 86400) -> None:
    if not jti:
        return
    r = _revocation_redis()
    if r is not None:
        try:
            r.setex(f"revoked-jti:{jti}", max(60, int(ttl_seconds)), "1")
            return
        except Exception:
            global _revocation_warned
            if not _revocation_warned:
                _revocation_warned = True
                import logging as _logging
                _logging.getLogger("cipherpost.auth").warning(
                    "revocation falling back to in-memory set (Redis unavailable)")
    _revoked_jti.add(jti)
    if len(_revoked_jti) > 10_000:
        _revoked_jti.clear()
        _revoked_jti.add(jti)


def is_token_revoked(jti: str) -> bool:
    if not jti:
        return False  # pre-revocation-era tokens carry no jti; sv still applies
    r = _revocation_redis()
    if r is not None:
        try:
            if r.get(f"revoked-jti:{jti}"):
                return True
        except Exception:
            pass
    return jti in _revoked_jti


def reset_revocations() -> None:
    """Test-only."""
    _revoked_jti.clear()


# --------------------------------------------------------------------------
# MFA step-up tickets: short-lived (5 min), single-use, scope mfa-verify.
# Issued after password (or OIDC) when the account needs MFA; exchanged for
# a session token after a valid TOTP/recovery code. Same burn semantics as
# SSE tickets.
# --------------------------------------------------------------------------

_MFA_TICKET_TTL = 300
_used_mfa_tickets: set[str] = set()


def create_mfa_ticket(sub: str, org_id: str) -> str:
    return create_access_token(sub, org_id, "", expires_in=_MFA_TICKET_TTL,
                               extra={"scope": "mfa-verify", "typ": "mfa-ticket",
                                      "jti": secrets.token_hex(8)})


def consume_mfa_ticket(token: str) -> dict:
    claims = decode_token(token)
    if claims.get("scope") != "mfa-verify":
        raise ValueError("not an MFA ticket (scope)")
    jti = claims.get("jti") or ""
    if not jti:
        raise ValueError("ticket missing jti")
    r = _login_redis()
    key = f"mfa-ticket:{jti}"
    if r is not None:
        try:
            ok = r.set(key, "1", nx=True, ex=_MFA_TICKET_TTL)
            if not ok:
                raise ValueError("ticket already used")
            return claims
        except ValueError:
            raise
        except Exception:
            pass
    if jti in _used_mfa_tickets:
        raise ValueError("ticket already used")
    _used_mfa_tickets.add(jti)
    if len(_used_mfa_tickets) > 10_000:
        _used_mfa_tickets.clear()
        _used_mfa_tickets.add(jti)
    return claims


# --------------------------------------------------------------------------
# API keys: `cp_<32 hex>`, only SHA-256 hash stored
# --------------------------------------------------------------------------

def generate_api_key() -> tuple[str, str, str]:
    """Return (raw_key, key_hash, prefix). Raw key is shown once at creation."""
    raw = "cp_" + secrets.token_hex(16)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return raw, digest, raw[:11]


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# --------------------------------------------------------------------------
# Roles + FastAPI dependencies
# --------------------------------------------------------------------------

ROLE_ORDER = {"auditor": 0, "analyst": 1, "admin": 2}


@dataclass
class AuthContext:
    user_id: str | None
    email: str
    org_id: str
    role: str
    via: str  # "jwt" | "api_key"


_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    from app.models.entities import User, ApiKey  # lazy: avoid import cycle

    # 1) API key via X-API-Key header (programmatic access)
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        digest = hash_api_key(api_key)
        row = (await db.execute(
            select(ApiKey).where(ApiKey.key_hash == digest))).scalars().first()
        if row is None or row.revoked:
            raise HTTPException(401, "Invalid API key")
        user = await db.get(User, row.user_id)
        if user is None or not user.is_active:
            raise HTTPException(401, "API key owner inactive")
        try:
            from datetime import datetime, timezone
            user.last_login = datetime.now(timezone.utc)
            await db.commit()
        except Exception:
            pass
        return AuthContext(user_id=user.id, email=user.email,
                           org_id=user.org_id, role=user.role.value,
                           via="api_key")

    # 2) JWT Bearer (dashboard login session)
    if creds is None or not creds.credentials:
        raise HTTPException(401, "Not authenticated")
    try:
        claims = decode_token(creds.credentials)
    except ValueError:
        raise HTTPException(401, "Invalid or expired token")
    if is_token_revoked(claims.get("jti", "")):
        raise HTTPException(401, "Session revoked")
    user = await db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(401, "User inactive or deleted")
    if user.org_id != claims.get("org"):
        raise HTTPException(401, "Token org mismatch")
    # Session version: bumped by revoke-all / password change. Tokens issued
    # before revocation carry an older sv (missing sv means version 1).
    token_sv = claims.get("sv", 1)
    try:
        token_sv = int(token_sv)
    except Exception:
        raise HTTPException(401, "Invalid session version")
    if token_sv != int(getattr(user, "session_version", 1) or 1):
        raise HTTPException(401, "Session revoked")
    return AuthContext(user_id=user.id, email=user.email,
                       org_id=user.org_id, role=user.role.value, via="jwt")


def require_roles(*roles: str):
    """Dependency factory: caller must have one of the given roles or higher.

    Hierarchy: auditor < analyst < admin. Passing "analyst" allows analyst
    and admin; passing "admin" allows only admin.
    """
    needed = min(ROLE_ORDER[r] for r in roles)

    async def _dep(ctx: AuthContext = Depends(get_current_user)) -> AuthContext:
        if ROLE_ORDER.get(ctx.role, -1) < needed:
            raise HTTPException(403, "Insufficient role")
        return ctx

    return _dep


async def log_audit(db: AsyncSession, org_id: str, actor: str,
                    action: str, resource: str = "",
                    detail: dict | None = None) -> None:
    """Best-effort audit write; never breaks the request it annotates."""
    try:
        from app.models.entities import AuditLog
        db.add(AuditLog(org_id=org_id, actor=actor, action=action,
                        resource=resource, detail=detail or {}))
        await db.commit()
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass


# --------------------------------------------------------------------------
# SSE tickets: short-lived (<=60s), single-use, scope-limited (live:read)
# --------------------------------------------------------------------------

_SSE_TICKET_TTL = 60
_used_sse_tickets: set[str] = set()


def create_sse_ticket(sub: str, org_id: str, role: str) -> str:
    """Issue a single-use ticket for EventSource streams (scope live:read)."""
    return create_access_token(sub, org_id, role, expires_in=_SSE_TICKET_TTL,
                               extra={"scope": "live:read", "typ": "sse-ticket",
                                      "jti": secrets.token_hex(8)})


def consume_sse_ticket(token: str) -> dict:
    """Validate + burn a ticket. Raises ValueError if invalid/reused/expired."""
    claims = decode_token(token)
    if claims.get("scope") != "live:read":
        raise ValueError("not an SSE ticket (scope)")
    jti = claims.get("jti") or ""
    if not jti:
        raise ValueError("ticket missing jti")
    # Single-use: Redis SETNX when available, else in-memory set.
    r = _login_redis()
    key = f"sse-ticket:{jti}"
    if r is not None:
        try:
            ok = r.set(key, "1", nx=True, ex=_SSE_TICKET_TTL)
            if not ok:
                raise ValueError("ticket already used")
            return claims
        except ValueError:
            raise
        except Exception:
            pass
    if jti in _used_sse_tickets:
        raise ValueError("ticket already used")
    _used_sse_tickets.add(jti)
    # Bound memory: keep only recent 10k
    if len(_used_sse_tickets) > 10_000:
        _used_sse_tickets.clear()
        _used_sse_tickets.add(jti)
    return claims
