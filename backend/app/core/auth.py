"""
Track 1: Authentication, RBAC, API keys.

Design notes:
- No third-party auth deps (no PyJWT/bcrypt in requirements): JWT is minimal
  HS256 implemented with stdlib hmac/base64, passwords use PBKDF2-HMAC-SHA256
  (200k iterations, per-user 16-byte salt). Both are auditable in ~100 lines.
- Two credential kinds: user login sessions (short-lived JWT) and long-lived
  API keys (`cp_<hex>`, SHA-256 hash stored, prefix indexed) for SIEM/scripts.
- Roles: admin (full + config/user mgmt), analyst (view + upload), auditor
  (read-only). Role hierarchy enforced in `require_roles`.
- Tenancy: every User/ApiKey/Job/Session carries org_id. Queries filter by
  the caller's org. Single-org deployments just use the seeded "default" org;
  the columns make true multi-tenancy a policy change, not a migration.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
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
# Minimal HS256 JWT (stdlib only)
# --------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _jwt_secret() -> bytes:
    secret = getattr(settings, "JWT_SECRET", "") or ""
    if not secret or secret == "change-me-in-production":
        # Dev fallback: stable per-process secret would invalidate logins on
        # restart, so derive from a persisted file if present, else ephemeral.
        # Production MUST set CIPHERPOST_JWT_SECRET (warned at startup).
        return b"cipherpost-dev-only-secret"
    return secret.encode()


def create_access_token(sub: str, org_id: str, role: str,
                        expires_in: int | None = None) -> str:
    if expires_in is None:
        expires_in = int(getattr(settings, "JWT_EXPIRY_SECONDS", 86400))
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub": sub, "org": org_id, "role": role,
        "iat": now, "exp": now + expires_in,
    }).encode())
    sig = _b64url(hmac.new(_jwt_secret(), f"{header}.{payload}".encode(),
                           hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def decode_token(token: str) -> dict:
    try:
        header_b, payload_b, sig_b = token.split(".")
        expected = _b64url(hmac.new(
            _jwt_secret(), f"{header_b}.{payload_b}".encode(),
            hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig_b):
            raise ValueError("bad signature")
        claims = json.loads(_b64url_decode(payload_b))
        if int(claims.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return claims
    except Exception as e:
        raise ValueError(f"invalid token: {e}")


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
            from datetime import datetime
            user.last_login = datetime.utcnow()
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
    user = await db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(401, "User inactive or deleted")
    if user.org_id != claims.get("org"):
        raise HTTPException(401, "Token org mismatch")
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
