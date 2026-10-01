"""
FastAPI application — CipherPost API.

Endpoints:
  POST   /api/v1/upload          Upload PCAP → create analysis job
  GET    /api/v1/jobs             List all jobs
  GET    /api/v1/jobs/{id}       Job status + progress
  GET    /api/v1/jobs/{id}/sessions  Sessions for a job
  GET    /api/v1/jobs/{id}/findings  Findings for a job (severity-sorted)
  GET    /api/v1/jobs/{id}/report.{fmt}  Report: json, html, pdf
  GET    /api/v1/health           Health check
  GET    /metrics                 Prometheus metrics (if available)
"""
from __future__ import annotations

import os
import uuid
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import asyncio
import json as _json

from app.core.config import settings
from app.core.database import get_db, init_db
from app.core.auth import (
    AuthContext, get_current_user, require_roles,
    hash_password, verify_password, create_access_token,
    generate_api_key, log_audit,
)
from app.models.entities import (
    AnalysisJob, Session, Finding, ShaPRow, SessionSummary, JobStatus, Severity,
    Organization, User, UserRole, ApiKey, AuditLog,
)

app = FastAPI(
    title="CipherPost",
    version=settings.APP_VERSION,
    description="AI-assisted passive network forensic analysis of email infrastructure cryptography",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list(),
    allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await init_db()


@app.get("/api/v1/health")
async def health():
    """Health reflecting real state: DB, Redis, lag, DLQ, drops, migrations.

    status is ok/degraded/down. Cheap enough for load balancers (2s caps).
    """
    from app.live.health import collect_health
    try:
        return await collect_health()
    except Exception as e:
        return {"status": "down", "version": settings.APP_VERSION, "error": str(e)[:200]}


@app.get("/api/v1/health/live")
async def health_live():
    """Kubernetes liveness: the process is alive (no dependency checks)."""
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/api/v1/health/ready")
async def health_ready():
    """Kubernetes readiness: DB + Redis + migrations at head."""
    from app.live.health import readiness
    try:
        ready, detail = await readiness()
        if not ready:
            return JSONResponse({"status": "not-ready", **detail}, status_code=503)
        return {"status": "ready", **detail}
    except Exception as e:
        return JSONResponse({"status": "not-ready", "error": str(e)[:200]},
                            status_code=503)


# --- auth / users / api keys / audit (track 1) -------------------------------
# NOTE (contract change, explicit): every /api/v1 route except /health and
# /metrics now requires authentication (JWT Bearer from dashboard login, or
# X-API-Key for programmatic access). Unauthenticated calls get 401;
# under-privileged calls get 403. See docs/auth.md.

@app.post("/api/v1/auth/login")
async def login(body: dict, request: Request, db: AsyncSession = Depends(get_db)):
    from datetime import datetime, timezone
    from app.core.auth import (
        is_login_locked, record_login_failure, record_login_success,
    )
    email = (body.get("email") or "").strip().lower()
    client_ip = (request.client.host if request.client else "unknown")
    acct_key = f"login:acct:{email or 'unknown'}"
    ip_key = f"login:ip:{client_ip}"
    if email and is_login_locked(acct_key, ip_key):
        raise HTTPException(401, "Invalid email or password")
    # Break-glass platform admin (disabled when env empty; every use audited).
    if email and _break_glass_configured() and email == settings.BREAK_GLASS_EMAIL.strip().lower():
        return await _break_glass_login(body.get("password") or "", request, db)
    if settings.DISABLE_PASSWORD_LOGIN:
        await log_audit(db, "unknown", email or "unknown", "auth.login.failed",
                        "session", {"reason": "password-login-disabled", "ip": client_ip})
        raise HTTPException(403, "Password login is disabled (SSO enforced)")
    user = (await db.execute(select(User).where(User.email == email))).scalars().first()
    if user is None or not user.is_active or not verify_password(
            body.get("password") or "", user.password_hash):
        record_login_failure(acct_key, ip_key)
        # Generic error (no user enumeration) + audit failure with org guard.
        try:
            org = user.org_id if user is not None else "unknown"
            await log_audit(db, org, email or "unknown", "auth.login.failed",
                            "session", {"ip": client_ip})
        except Exception:
            pass
        raise HTTPException(401, "Invalid email or password")
    record_login_success(acct_key, ip_key)
    return await _finish_password_login(user, request, db)


async def _finish_password_login(user, request: Request, db: AsyncSession):
    """Shared post-password tail: MFA step-up or session token. Never 500s."""
    from datetime import datetime, timezone
    from app.core.auth import create_mfa_ticket
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    if await _mfa_required(user, db):
        ticket = create_mfa_ticket(user.id, user.org_id)
        await log_audit(db, user.org_id, user.email, "auth.mfa.challenged", "session")
        return {"mfa_required": True, "mfa_ticket": ticket,
                "user": {"id": user.id, "email": user.email,
                         "role": user.role.value, "org_id": user.org_id}}
    token = create_access_token(user.id, user.org_id, user.role.value,
                                session_version=int(getattr(user, "session_version", 1) or 1))
    await log_audit(db, user.org_id, user.email, "auth.login", "session")
    return {"token": token,
            "user": {"id": user.id, "email": user.email,
                     "role": user.role.value, "org_id": user.org_id}}


def _break_glass_configured() -> bool:
    return bool((settings.BREAK_GLASS_EMAIL or "").strip()
                and (settings.BREAK_GLASS_PASSWORD or ""))


async def _break_glass_login(password: str, request: Request, db: AsyncSession):
    """Break-glass path: existing platform-admin user + env password. Audited."""
    import hmac as _hmac
    from datetime import datetime, timezone
    email = settings.BREAK_GLASS_EMAIL.strip().lower()
    client_ip = (request.client.host if request.client else "unknown")
    user = (await db.execute(select(User).where(User.email == email))).scalars().first()
    ok = (user is not None and user.is_active
          and bool(getattr(user, "is_platform_admin", False))
          and _hmac.compare_digest(password, settings.BREAK_GLASS_PASSWORD))
    if not ok:
        from app.core.auth import record_login_failure
        record_login_failure(f"login:acct:{email}", f"login:ip:{client_ip}")
        try:
            await log_audit(db, user.org_id if user else "unknown", email,
                            "auth.login.break_glass.failed", "session", {"ip": client_ip})
        except Exception:
            pass
        raise HTTPException(401, "Invalid email or password")
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    token = create_access_token(user.id, user.org_id, user.role.value,
                                session_version=int(getattr(user, "session_version", 1) or 1))
    await log_audit(db, user.org_id, user.email, "auth.login.break_glass", "session",
                    {"ip": client_ip})
    return {"token": token, "break_glass": True,
            "user": {"id": user.id, "email": user.email,
                     "role": user.role.value, "org_id": user.org_id}}


async def _mfa_required(user, db: AsyncSession) -> bool:
    """True when the user enrolled MFA or their org mandates it."""
    if bool(getattr(user, "mfa_enabled", False)):
        return True
    try:
        required = {o.strip() for o in
                    (settings.MFA_REQUIRED_ORGS or "").split(",") if o.strip()}
        if not required:
            return False
        from app.models.entities import Organization
        org = await db.get(Organization, user.org_id)
        return bool(org is not None and org.name in required)
    except Exception:
        return False


@app.get("/api/v1/auth/me")
async def me(ctx: AuthContext = Depends(get_current_user)):
    return {"id": ctx.user_id, "email": ctx.email,
            "role": ctx.role, "org_id": ctx.org_id, "via": ctx.via}


# --- SSO / MFA / sessions (phase 3 task 1) ---------------------------------

@app.get("/api/v1/auth/oidc/start")
async def oidc_start(redirect_uri: str = Query(...)):
    from app.core import oidc as _oidc
    if not _oidc.enabled():
        raise HTTPException(404, "SSO is not configured")
    try:
        url, state = _oidc.new_authorize_url(redirect_uri)
    except Exception as e:
        raise HTTPException(503, f"SSO unavailable: {e}")
    return {"url": url, "state": state}


@app.post("/api/v1/auth/oidc/callback")
async def oidc_callback(body: dict, request: Request,
                        db: AsyncSession = Depends(get_db)):
    """Exchange code+state, verify the ID token, provision/find the user."""
    from datetime import datetime, timezone
    from app.core import oidc as _oidc
    from app.core.auth import create_mfa_ticket
    if not _oidc.enabled():
        raise HTTPException(404, "SSO is not configured")
    client_ip = (request.client.host if request.client else "unknown")
    try:
        stored = _oidc.consume_state((body.get("state") or "").strip())
    except ValueError as e:
        await log_audit(db, "unknown", "sso", "auth.sso.failed", "callback",
                        {"ip": client_ip, "reason": str(e)[:200]})
        raise HTTPException(401, "Invalid SSO state (possible replay)")
    try:
        tokens = _oidc.exchange_code((body.get("code") or "").strip(),
                                     stored["verifier"],
                                     (body.get("redirect_uri") or "").strip())
        claims = _oidc.verify_id_token(tokens.get("id_token", ""), stored.get("nonce"))
    except ValueError as e:
        await log_audit(db, "unknown", "sso", "auth.sso.failed", "callback",
                        {"ip": client_ip, "reason": str(e)[:200]})
        raise HTTPException(401, "SSO verification failed")
    role, org_name = _oidc.map_role_org(claims)
    email = str(claims.get("email", "") or "").strip().lower()
    sub = str(claims.get("sub", ""))
    if not email or "@" not in email or not sub:
        await log_audit(db, "unknown", email or "sso", "auth.sso.failed",
                        "callback", {"reason": "missing email/sub claim"})
        raise HTTPException(401, "SSO verification failed")
    user = (await db.execute(select(User).where(User.oidc_sub == sub))).scalars().first()
    if user is None:
        user = (await db.execute(select(User).where(User.email == email))).scalars().first()
        if user is not None and getattr(user, "oidc_sub", None) not in (None, sub):
            await log_audit(db, user.org_id, email, "auth.sso.failed", "callback",
                            {"reason": "oidc sub mismatch"})
            raise HTTPException(403, "SSO account conflict")
    if user is None:
        if not settings.OIDC_JIT_PROVISIONING:
            await log_audit(db, "unknown", email, "auth.sso.failed", "callback",
                            {"reason": "jit disabled"})
            raise HTTPException(403, "SSO account not provisioned")
        import uuid as _uuid
        from app.models.entities import Organization
        org = (await db.execute(
            select(Organization).where(Organization.name == org_name))).scalars().first()
        if org is None:
            org = (await db.execute(
                select(Organization).where(Organization.name == settings.DEFAULT_ORG_NAME))).scalars().first()
        user = User(id="user-" + _uuid.uuid4().hex[:12], org_id=org.id, email=email,
                    password_hash=hash_password(secrets_token_hex()),
                    role=UserRole(role), is_active=True, oidc_sub=sub)
        db.add(user)
        await db.commit()
        await log_audit(db, org.id, email, "auth.sso.provisioned", "user",
                        {"role": role, "org": org.name})
    if not user.is_active:
        raise HTTPException(401, "User inactive or deleted")
    if getattr(user, "oidc_sub", None) is None:
        user.oidc_sub = sub
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    if await _mfa_required(user, db):
        ticket = create_mfa_ticket(user.id, user.org_id)
        await log_audit(db, user.org_id, user.email, "auth.mfa.challenged", "session")
        return {"mfa_required": True, "mfa_ticket": ticket}
    token = create_access_token(user.id, user.org_id, user.role.value,
                                session_version=int(getattr(user, "session_version", 1) or 1))
    await log_audit(db, user.org_id, user.email, "auth.login.sso", "session")
    return {"token": token,
            "user": {"id": user.id, "email": user.email,
                     "role": user.role.value, "org_id": user.org_id}}


def secrets_token_hex() -> str:
    import secrets as _s
    return _s.token_hex(32)


@app.post("/api/v1/auth/mfa/enroll")
async def mfa_enroll(ctx: AuthContext = Depends(get_current_user),
                     db: AsyncSession = Depends(get_db)):
    """Start TOTP enrollment. Returns otpauth URI + one-time recovery codes."""
    from app.core import mfa as _mfa
    if not settings.MFA_ENROLL_ALLOW:
        raise HTTPException(403, "MFA enrollment is disabled")
    user = await db.get(User, ctx.user_id)
    if user is None:
        raise HTTPException(401, "User inactive or deleted")
    secret = _mfa.random_secret()
    codes = _mfa.new_recovery_codes()
    user.mfa_secret_enc = _mfa.encrypt_secret(secret)
    user.mfa_recovery = [_mfa.hash_recovery_code(c) for c in codes]
    await db.commit()
    await log_audit(db, user.org_id, user.email, "auth.mfa.enroll_started", "mfa")
    return {"otpauth_uri": _mfa.otpauth_uri(secret, user.email, settings.MFA_ISSUER_NAME),
            "recovery_codes": codes,
            "warning": "Store recovery codes now; secrets/recovery hashes only from here on"}


@app.post("/api/v1/auth/mfa/confirm")
async def mfa_confirm(body: dict,
                      ctx: AuthContext = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    """Confirm enrollment with a TOTP code from the authenticator app."""
    from app.core import mfa as _mfa
    user = await db.get(User, ctx.user_id)
    if user is None or not getattr(user, "mfa_secret_enc", None):
        raise HTTPException(400, "No pending MFA enrollment")
    try:
        secret = _mfa.decrypt_secret(user.mfa_secret_enc)
    except ValueError:
        raise HTTPException(500, "MFA secret unreadable; re-enroll")
    if not _mfa.verify_code(secret, body.get("code") or ""):
        await log_audit(db, user.org_id, user.email, "auth.mfa.failed", "mfa")
        raise HTTPException(401, "Invalid MFA code")
    user.mfa_enabled = True
    await db.commit()
    await log_audit(db, user.org_id, user.email, "auth.mfa.enabled", "mfa")
    return {"status": "enabled"}


@app.post("/api/v1/auth/mfa/verify")
async def mfa_verify(body: dict, request: Request,
                     db: AsyncSession = Depends(get_db)):
    """Exchange an MFA ticket + TOTP (or recovery code) for a session token."""
    from app.core import mfa as _mfa
    from app.core.auth import consume_mfa_ticket
    from datetime import datetime, timezone
    client_ip = (request.client.host if request.client else "unknown")
    try:
        claims = consume_mfa_ticket((body.get("mfa_ticket") or "").strip())
    except ValueError:
        raise HTTPException(401, "Invalid or expired MFA ticket")
    user = await db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(401, "User inactive or deleted")
    ukey = f"mfa:{user.id}"
    if _mfa.mfa_locked(ukey):
        raise HTTPException(401, "Invalid MFA code")
    ok = False
    try:
        secret = _mfa.decrypt_secret(user.mfa_secret_enc or "")
        ok = _mfa.verify_code(secret, body.get("code") or "")
    except ValueError:
        ok = False
    if not ok and body.get("recovery_code"):
        remaining = _mfa.consume_recovery_code(user.mfa_recovery or [],
                                               body.get("recovery_code") or "")
        if remaining is not None:
            user.mfa_recovery = remaining
            ok = True
    if not ok:
        _mfa.record_mfa_failure(ukey)
        await log_audit(db, user.org_id, user.email, "auth.mfa.failed", "session",
                        {"ip": client_ip})
        raise HTTPException(401, "Invalid MFA code")
    _mfa.record_mfa_success(ukey)
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    token = create_access_token(user.id, user.org_id, user.role.value,
                                session_version=int(getattr(user, "session_version", 1) or 1))
    await log_audit(db, user.org_id, user.email, "auth.login", "session",
                    {"mfa": True})
    return {"token": token,
            "user": {"id": user.id, "email": user.email,
                     "role": user.role.value, "org_id": user.org_id}}


@app.post("/api/v1/auth/mfa/disable")
async def mfa_disable(body: dict,
                      ctx: AuthContext = Depends(require_roles("admin")),
                      db: AsyncSession = Depends(get_db)):
    """Admin reset of a user's MFA (lost authenticator path). Audited."""
    target_id = (body.get("user_id") or "").strip()
    user = await db.get(User, target_id)
    if user is None or user.org_id != ctx.org_id:
        raise HTTPException(404, "User not found")
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    user.mfa_recovery = None
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "auth.mfa.disabled", user.email, {})
    return {"status": "disabled"}


@app.post("/api/v1/auth/logout")
async def logout(request: Request,
                 ctx: AuthContext = Depends(get_current_user),
                 db: AsyncSession = Depends(get_db)):
    """Revoke the presenting token (deny-listed until its expiry)."""
    from app.core.auth import revoke_token, decode_token
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            claims = decode_token(auth[7:].strip())
            ttl = max(60, int(claims.get("exp", 0)) - int(__import__("time").time()))
            revoke_token(claims.get("jti", ""), ttl)
        except ValueError:
            pass
    await log_audit(db, ctx.org_id, ctx.email, "auth.logout", "session")
    return {"status": "logged out"}


@app.post("/api/v1/auth/revoke-all")
async def revoke_all_sessions(body: dict,
                              ctx: AuthContext = Depends(get_current_user),
                              db: AsyncSession = Depends(get_db)):
    """Bump session version: kills every session for the target user."""
    target_id = ((body.get("user_id") if isinstance(body, dict) else None) or ctx.user_id or "")
    if target_id != ctx.user_id and ctx.role != "admin":
        raise HTTPException(403, "Admins only for other users")
    user = await db.get(User, target_id)
    if user is None or (user.org_id != ctx.org_id and ctx.role != "admin"):
        raise HTTPException(404, "User not found")
    user.session_version = int(getattr(user, "session_version", 1) or 1) + 1
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "auth.sessions.revoked", user.email, {})
    return {"status": "revoked"}


@app.get("/api/v1/users")
async def list_users(ctx: AuthContext = Depends(require_roles("admin")),
                     db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(User).where(User.org_id == ctx.org_id))).scalars().all()
    return [{"id": u.id, "email": u.email, "role": u.role.value,
             "is_active": u.is_active,
             "created_at": u.created_at.isoformat() if u.created_at else None,
             "last_login": u.last_login.isoformat() if u.last_login else None}
            for u in rows]


@app.post("/api/v1/users")
async def create_user(body: dict,
                      ctx: AuthContext = Depends(require_roles("admin")),
                      db: AsyncSession = Depends(get_db)):
    import uuid
    email = (body.get("email") or "").strip().lower()
    role = (body.get("role") or "analyst").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Valid email required")
    if role not in ("admin", "analyst", "auditor"):
        raise HTTPException(400, "role must be admin|analyst|auditor")
    if not body.get("password") or len(body["password"]) < 10:
        raise HTTPException(400, "password must be >= 10 chars")
    exists = (await db.execute(select(User).where(User.email == email))).scalars().first()
    if exists:
        raise HTTPException(409, "User already exists")
    user = User(id="user-" + uuid.uuid4().hex[:12], org_id=ctx.org_id,
                email=email, password_hash=hash_password(body["password"]),
                role=UserRole(role), is_active=True)
    db.add(user)
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "user.create", email,
                    {"role": role})
    return {"id": user.id, "email": user.email, "role": user.role.value}


@app.patch("/api/v1/users/{user_id}")
async def update_user(user_id: str, body: dict,
                      ctx: AuthContext = Depends(require_roles("admin")),
                      db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if user is None or user.org_id != ctx.org_id:
        raise HTTPException(404, "User not found")
    if user.id == ctx.user_id and body.get("is_active") is False:
        raise HTTPException(400, "Cannot deactivate yourself")
    if "role" in body:
        if body["role"] not in ("admin", "analyst", "auditor"):
            raise HTTPException(400, "role must be admin|analyst|auditor")
        user.role = UserRole(body["role"])
    if "is_active" in body:
        user.is_active = bool(body["is_active"])
    if body.get("password"):
        if len(body["password"]) < 10:
            raise HTTPException(400, "password must be >= 10 chars")
        user.password_hash = hash_password(body["password"])
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "user.update", user.email, body and
                    {k: v for k, v in body.items() if k != "password"})
    return {"id": user.id, "email": user.email, "role": user.role.value,
            "is_active": user.is_active}


@app.get("/api/v1/api-keys")
async def list_api_keys(ctx: AuthContext = Depends(require_roles("analyst")),
                        db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(ApiKey).where(ApiKey.org_id == ctx.org_id,
                             ApiKey.revoked.is_(False)))).scalars().all()
    return [{"id": k.id, "name": k.name, "prefix": k.prefix,
             "created_at": k.created_at.isoformat() if k.created_at else None,
             "expires_at": k.expires_at.isoformat() if k.expires_at else None}
            for k in rows]


@app.post("/api/v1/api-keys")
async def create_api_key(body: dict,
                         ctx: AuthContext = Depends(require_roles("admin")),
                         db: AsyncSession = Depends(get_db)):
    import uuid
    from datetime import datetime, timezone, timedelta
    name = (body.get("name") or "").strip() or "siem-integration"
    raw, digest, prefix = generate_api_key()
    expires_at = None
    if body.get("expires_days"):
        expires_at = datetime.now(timezone.utc) + timedelta(days=int(body["expires_days"]))
    db.add(ApiKey(id="key-" + uuid.uuid4().hex[:12], org_id=ctx.org_id,
                  user_id=ctx.user_id, name=name, key_hash=digest,
                  prefix=prefix, expires_at=expires_at))
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "apikey.create", name,
                    {"prefix": prefix})
    # raw key is returned ONCE — only the hash is stored
    return {"raw_key": raw, "prefix": prefix,
            "warning": "Store this key now; it cannot be retrieved again"}


@app.delete("/api/v1/api-keys/{key_id}")
async def revoke_api_key(key_id: str,
                         ctx: AuthContext = Depends(require_roles("admin")),
                         db: AsyncSession = Depends(get_db)):
    key = await db.get(ApiKey, key_id)
    if key is None or key.org_id != ctx.org_id:
        raise HTTPException(404, "API key not found")
    key.revoked = True
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "apikey.revoke", key.name,
                    {"prefix": key.prefix})
    return {"status": "revoked", "prefix": key.prefix}


@app.get("/api/v1/audit")
async def list_audit(limit: int = Query(100, ge=1, le=500),
                     action: str | None = Query(None),
                     ctx: AuthContext = Depends(get_current_user),
                     db: AsyncSession = Depends(get_db)):
    if ctx.role not in ("admin", "auditor"):
        raise HTTPException(403, "Admins and auditors only")
    q = select(AuditLog).where(AuditLog.org_id == ctx.org_id)
    if action:
        q = q.where(AuditLog.action == action)
    q = q.order_by(AuditLog.id.desc()).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [{"id": r.id, "actor": r.actor, "action": r.action,
             "resource": r.resource, "detail": r.detail,
             "created_at": r.created_at.isoformat() if r.created_at else None}
            for r in rows]


# --- suppressions (phase 2 task 3: accepted-risk exceptions) ------------------

def _sup_to_dict(s) -> dict:
    from app.proactive.suppressions import is_active as _is_active
    return {"id": s.id, "org_id": s.org_id, "rule_id": s.rule_id,
            "scope": s.scope, "reason": s.reason, "created_by": s.created_by,
            "status": s.status,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "active": _is_active(s.status, s.expires_at)}


# --- organizations + org-scoped agent ingest (phase 3 task 2) ---------------

def require_platform_admin():
    async def _dep(ctx: AuthContext = Depends(get_current_user),
                   db: AsyncSession = Depends(get_db)) -> AuthContext:
        user = await db.get(User, ctx.user_id) if ctx.user_id else None
        if user is None or not bool(getattr(user, "is_platform_admin", False)):
            raise HTTPException(403, "Platform admins only")
        return ctx
    return _dep


@app.get("/api/v1/orgs")
async def list_orgs(ctx: AuthContext = Depends(require_platform_admin()),
                    db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Organization).order_by(Organization.name))).scalars().all()
    return [{"id": o.id, "name": o.name,
             "created_at": o.created_at.isoformat() if o.created_at else None} for o in rows]


@app.post("/api/v1/orgs")
async def create_org(body: dict,
                     ctx: AuthContext = Depends(require_platform_admin()),
                     db: AsyncSession = Depends(get_db)):
    import uuid as _uuid
    name = (body.get("name") or "").strip()
    if not name or len(name) > 256:
        raise HTTPException(400, "Valid org name required")
    exists = (await db.execute(
        select(Organization).where(Organization.name == name))).scalars().first()
    if exists:
        raise HTTPException(409, "Org already exists")
    org = Organization(id="org-" + _uuid.uuid4().hex[:12], name=name)
    db.add(org)
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "org.create", name, {})
    return {"id": org.id, "name": org.name}


@app.post("/api/v1/admin/assume")
async def assume_org(body: dict,
                     ctx: AuthContext = Depends(require_platform_admin()),
                     db: AsyncSession = Depends(get_db)):
    """Audited cross-org access: platform admin gets a short-lived token scoped
    to another org. The reason is required and audit-logged; silent reads of
    tenant data are not possible without this trail."""
    from datetime import timedelta
    reason = (body.get("reason") or "").strip()
    org_id = (body.get("org_id") or "").strip()
    if not reason or not org_id:
        raise HTTPException(400, "org_id and reason are required")
    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "Org not found")
    user = await db.get(User, ctx.user_id)
    token = create_access_token(user.id, org.id, user.role.value,
                                expires_in=3600,
                                extra={"assumed": True, "assumed_by": ctx.email},
                                session_version=int(getattr(user, "session_version", 1) or 1))
    await log_audit(db, org.id, ctx.email, "admin.assume_org", org.name,
                    {"reason": reason, "expires_in": 3600})
    return {"token": token, "org_id": org.id, "expires_in": 3600,
            "warning": "This access is audit-logged"}


def _agent_token_helpers():
    from app.core.auth import generate_api_key, hash_api_key
    return generate_api_key, hash_api_key


@app.get("/api/v1/agent-tokens")
async def list_agent_tokens(ctx: AuthContext = Depends(require_roles("admin")),
                            db: AsyncSession = Depends(get_db)):
    from app.models.entities import AgentToken
    rows = (await db.execute(
        select(AgentToken).where(AgentToken.org_id == ctx.org_id,
                                 AgentToken.revoked.is_(False)))).scalars().all()
    return [{"id": t.id, "name": t.name, "prefix": t.prefix,
             "created_by": t.created_by,
             "created_at": t.created_at.isoformat() if t.created_at else None,
             "expires_at": t.expires_at.isoformat() if t.expires_at else None}
            for t in rows]


@app.post("/api/v1/agent-tokens")
async def create_agent_token(body: dict,
                             ctx: AuthContext = Depends(require_roles("admin")),
                             db: AsyncSession = Depends(get_db)):
    """Issue an org-scoped sensor credential. Raw token shown once, hash stored."""
    import uuid as _uuid
    from datetime import datetime, timezone, timedelta
    from app.models.entities import AgentToken
    generate_api_key, _ = _agent_token_helpers()
    name = (body.get("name") or "").strip() or "sensor"
    raw, digest, prefix = generate_api_key()
    raw = "cpat_" + raw[3:]  # agent namespace (still 32 hex entropy)
    expires_at = None
    if body.get("expires_days"):
        try:
            expires_at = datetime.now(timezone.utc) + timedelta(days=int(body["expires_days"]))
        except Exception:
            raise HTTPException(400, "expires_days must be an integer")
    from app.core.auth import hash_api_key
    db.add(AgentToken(id="at-" + _uuid.uuid4().hex[:12], org_id=ctx.org_id,
                      name=name, key_hash=hash_api_key(raw), prefix=raw[:11],
                      created_by=ctx.email, expires_at=expires_at))
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "agenttoken.create", name,
                    {"prefix": raw[:11]})
    return {"raw_token": raw, "prefix": raw[:11],
            "warning": "Store this token now; it cannot be retrieved again"}


@app.delete("/api/v1/agent-tokens/{token_id}")
async def revoke_agent_token(token_id: str,
                             ctx: AuthContext = Depends(require_roles("admin")),
                             db: AsyncSession = Depends(get_db)):
    from app.models.entities import AgentToken
    tok = await db.get(AgentToken, token_id)
    if tok is None or tok.org_id != ctx.org_id:
        raise HTTPException(404, "Agent token not found")
    tok.revoked = True
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "agenttoken.revoke", tok.name,
                    {"prefix": tok.prefix})
    return {"status": "revoked", "prefix": tok.prefix}


@app.post("/api/v1/ingest/sessions")
async def ingest_sessions(request: Request, db: AsyncSession = Depends(get_db)):
    """Authenticated sensor ingest: batched session metadata -> stream.

    Auth is an org-scoped agent token (X-Agent-Token). The org is stamped from
    the token — agents can never choose another org. Returns 429 with
    Retry-After when the pipeline is backed up (backpressure).
    """
    import gzip as _gzip
    import time as _time
    from datetime import datetime, timezone
    from app.core.auth import hash_api_key
    from app.models.entities import AgentToken
    raw_tok = request.headers.get("X-Agent-Token", "")
    if not raw_tok:
        raise HTTPException(401, "Agent token required")
    row = (await db.execute(
        select(AgentToken).where(AgentToken.key_hash == hash_api_key(raw_tok))
    )).scalars().first()
    if row is None or row.revoked:
        raise HTTPException(401, "Invalid agent token")
    if row.expires_at is not None:
        exp = row.expires_at
        if getattr(exp, "tzinfo", None) is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            raise HTTPException(401, "Agent token expired")
    try:
        body = await request.body()
        if (request.headers.get("content-encoding", "") or "").lower() == "gzip":
            body = _gzip.decompress(body)
        import json as _json
        data = _json.loads(body or b"{}")
    except Exception:
        raise HTTPException(400, "Invalid JSON body (or bad gzip)")
    sessions = data.get("sessions")
    if not isinstance(sessions, list) or not sessions:
        raise HTTPException(400, "sessions must be a non-empty list")
    if len(sessions) > settings.INGEST_MAX_BATCH:
        raise HTTPException(413, f"Batch over limit ({settings.INGEST_MAX_BATCH})")
    # Backpressure: refuse with 429 before the stream grows unbounded.
    try:
        import redis as _redis
        r = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
        if int(r.xlen(settings.SESSION_STREAM) or 0) > settings.INGEST_MAX_QUEUE:
            return JSONResponse({"error": "pipeline backed up, retry later",
                                 "accepted": 0},
                                status_code=429,
                                headers={"Retry-After": "5"})
    except HTTPException:
        raise
    except Exception:
        pass  # Redis down: accept and let the stream publisher buffer/fail
    from app.live import streams as _bus
    accepted, rejected = 0, 0
    try:
        r = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
    except Exception:
        r = None
    for entry in sessions:
        if not isinstance(entry, dict) or not entry.get("five_tuple") or not entry.get("protocol"):
            rejected += 1
            continue
        stamped = dict(entry)
        stamped["org_id"] = row.org_id  # token's org always wins
        stamped["agent"] = row.name
        stamped["ingested_at"] = _time.time()
        try:
            _bus.publish(r, settings.SESSION_STREAM, stamped)
            accepted += 1
        except Exception:
            rejected += 1
    return {"accepted": accepted, "rejected": rejected, "org_id": row.org_id}


@app.get("/api/v1/suppressions")
async def list_suppressions(status: str | None = Query(None),
                            ctx: AuthContext = Depends(get_current_user),
                            db: AsyncSession = Depends(get_db)):
    from app.models.entities import Suppression
    q = select(Suppression).where(Suppression.org_id == ctx.org_id)
    if status:
        q = q.where(Suppression.status == status)
    rows = (await db.execute(q.order_by(Suppression.id.desc()))).scalars().all()
    return [_sup_to_dict(s) for s in rows]


@app.get("/api/v1/suppressions/expiring-soon")
async def suppressions_expiring(days: int = Query(14, ge=1, le=90),
                                ctx: AuthContext = Depends(get_current_user),
                                db: AsyncSession = Depends(get_db)):
    from datetime import datetime, timezone, timedelta
    from app.models.entities import Suppression
    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=days)
    rows = (await db.execute(
        select(Suppression).where(Suppression.org_id == ctx.org_id,
                                  Suppression.status == "approved",
                                  Suppression.expires_at > now,
                                  Suppression.expires_at <= horizon)
        .order_by(Suppression.expires_at.asc()))).scalars().all()
    return [_sup_to_dict(s) for s in rows]


@app.post("/api/v1/suppressions")
async def create_suppression(body: dict,
                             ctx: AuthContext = Depends(require_roles("analyst")),
                             db: AsyncSession = Depends(get_db)):
    """Analyst+ can request; approved immediately iff config skips approval or
    the requester is an admin."""
    from datetime import datetime, timezone, timedelta
    from app.models.entities import Suppression
    rule_id = (body.get("rule_id") or "").strip()
    reason = (body.get("reason") or "").strip()
    if not rule_id or not reason:
        raise HTTPException(400, "rule_id and reason are required")
    try:
        days = int(body.get("expires_days", settings.SUPPRESSION_DEFAULT_DAYS))
    except Exception:
        raise HTTPException(400, "expires_days must be an integer")
    days = max(1, min(days, settings.SUPPRESSION_MAX_DAYS))
    now = datetime.now(timezone.utc)
    scope = body.get("scope") or {}
    if not isinstance(scope, dict):
        raise HTTPException(400, "scope must be an object")
    auto = (not settings.SUPPRESSION_REQUIRE_APPROVAL) or ctx.role == "admin"
    s = Suppression(org_id=ctx.org_id, rule_id=rule_id, scope=scope,
                    reason=reason, created_by=ctx.email,
                    status="approved" if auto else "pending",
                    created_at=now, expires_at=now + timedelta(days=days))
    db.add(s)
    await db.commit()
    await db.refresh(s)
    await log_audit(db, ctx.org_id, ctx.email, "suppression.create", rule_id,
                    {"scope": scope, "status": s.status, "days": days})
    return _sup_to_dict(s)


@app.patch("/api/v1/suppressions/{sup_id}")
async def update_suppression(sup_id: int, body: dict,
                             ctx: AuthContext = Depends(require_roles("admin")),
                             db: AsyncSession = Depends(get_db)):
    """Admin approve/reject/revoke (audit-logged)."""
    from app.models.entities import Suppression
    s = await db.get(Suppression, sup_id)
    if s is None or s.org_id != ctx.org_id:
        raise HTTPException(404, "Suppression not found")
    if "status" in body:
        if body["status"] not in ("approved", "rejected", "revoked"):
            raise HTTPException(400, "status must be approved|rejected|revoked")
        s.status = body["status"]
    if "reason" in body and body["reason"]:
        s.reason = str(body["reason"])
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "suppression.update",
                    str(sup_id), {"status": s.status})
    return _sup_to_dict(s)


@app.delete("/api/v1/suppressions/{sup_id}")
async def delete_suppression(sup_id: int,
                             ctx: AuthContext = Depends(require_roles("admin")),
                             db: AsyncSession = Depends(get_db)):
    from app.models.entities import Suppression
    s = await db.get(Suppression, sup_id)
    if s is None or s.org_id != ctx.org_id:
        raise HTTPException(404, "Suppression not found")
    await db.delete(s)
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "suppression.delete", str(sup_id), {})
    return {"status": "deleted"}


_GOSSIP_GAUGES: dict = {}


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint (merges gossip from workers as gauges)."""
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Gauge
        import re as _re

        def _gauge(worker: str, metric: str):
            name = "cipherpost_" + _re.sub(r"[^a-zA-Z0-9_]", "_", f"{worker}_{metric}")
            g = _GOSSIP_GAUGES.get(name)
            if g is None:
                g = Gauge(name, f"Gossiped worker metric {worker}.{metric}",
                          ["worker", "metric"])
                _GOSSIP_GAUGES[name] = g
            return g

        try:
            import redis as _redis
            r = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
            for k in r.keys("cipherpost:metrics:*"):
                try:
                    vals = r.get(k)
                    if isinstance(vals, bytes):
                        vals = vals.decode()
                    if isinstance(vals, str):
                        import json as _j
                        vals = _j.loads(vals)
                    worker = k.split(":")[-1]
                    for m, v in (vals or {}).items():
                        if m == "ts" or not isinstance(v, (int, float)):
                            continue
                        _gauge(worker, m).labels(worker=worker, metric=m).set(float(v))
                except Exception:
                    pass
        except Exception:
            pass
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except ImportError:
        return Response("prometheus-client not installed", media_type="text/plain")


# --- live SSE & extended API (stage 5) -----------------------------------

async def _sse_ctx(request: Request, token: str | None,
                   ticket: str | None,
                   db: AsyncSession) -> AuthContext:
    """SSE auth: EventSource cannot send headers, so accept a short-lived
    single-use ticket via ?ticket= (or legacy ?token= carrying a ticket).
    Main bearer tokens are NOT accepted in URLs to avoid log leaks; use the
    Authorization header for those (non-EventSource clients)."""
    raw = ticket or token
    if raw:
        from app.core.auth import consume_sse_ticket
        try:
            claims = consume_sse_ticket(raw)
        except ValueError:
            raise HTTPException(401, "Invalid or expired SSE ticket")
        user = await db.get(User, claims["sub"])
        if user is None or not user.is_active:
            raise HTTPException(401, "User inactive")
        return AuthContext(user_id=user.id, email=user.email,
                           org_id=user.org_id, role=user.role.value, via="jwt")
    # fall back to Authorization header via the standard dependency path
    creds = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        from fastapi.security import HTTPAuthorizationCredentials
        creds = HTTPAuthorizationCredentials(scheme="Bearer",
                                             credentials=auth[7:].strip())
    return await get_current_user(request, creds, db)


async def _pubsub_sse(channels: list[str], request: Request):
    """Yield SSE events from Redis pub/sub channels."""
    try:
        import redis.asyncio as aioredis
    except ImportError:
        yield "event: error\ndata: redis.asyncio not available\n\n"
        return
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    try:
        for ch in channels:
            await pubsub.subscribe(ch)
        # also psubscribe for wildcard?
        # send initial heartbeat
        yield "event: heartbeat\ndata: {\"status\":\"connected\"}\n\n"
        while True:
            if await request.is_disconnected():
                break
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg.get("type") == "message":
                ch = msg.get("channel", "unknown")
                data = msg.get("data", "{}")
                # normalize channel suffix
                ev = ch.split(":")[-1]
                yield f"event: {ev}\ndata: {data}\n\n"
            else:
                # heartbeat every 15s to keep connection alive
                yield ": ping\n\n"
                await asyncio.sleep(15)
    finally:
        try:
            await pubsub.unsubscribe()
            await pubsub.close()
            await r.close()
        except Exception:
            pass


@app.post("/api/v1/live/ticket")
async def live_ticket(ctx: AuthContext = Depends(get_current_user)):
    """Issue a short-lived single-use SSE ticket (scope live:read, 60s TTL).
    Frontend fetches this with the Bearer token, then opens EventSource with
    ?ticket= so the long-lived token never appears in URLs/logs."""
    from app.core.auth import create_sse_ticket
    return {"ticket": create_sse_ticket(ctx.user_id or "", ctx.org_id, ctx.role),
            "expires_in": 60, "scope": "live:read"}


@app.get("/api/v1/live/stream")
async def live_stream(request: Request, token: str | None = Query(None),
                      ticket: str | None = Query(None),
                      db: AsyncSession = Depends(get_db)):
    """Unified SSE stream: sessions + findings + alerts."""
    await _sse_ctx(request, token, ticket, db)
    chans = [f"{settings.LIVE_PUBSUB_PREFIX}:sessions", f"{settings.LIVE_PUBSUB_PREFIX}:findings", f"{settings.LIVE_PUBSUB_PREFIX}:alerts", f"{settings.LIVE_PUBSUB_PREFIX}:status"]
    return StreamingResponse(_pubsub_sse(chans, request), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/v1/live/sessions")
async def live_sessions(request: Request, token: str | None = Query(None),
                        ticket: str | None = Query(None),
                        db: AsyncSession = Depends(get_db)):
    await _sse_ctx(request, token, ticket, db)
    return StreamingResponse(_pubsub_sse([f"{settings.LIVE_PUBSUB_PREFIX}:sessions"], request), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/v1/live/findings")
async def live_findings(request: Request, token: str | None = Query(None),
                        ticket: str | None = Query(None),
                        db: AsyncSession = Depends(get_db)):
    await _sse_ctx(request, token, ticket, db)
    return StreamingResponse(_pubsub_sse([f"{settings.LIVE_PUBSUB_PREFIX}:findings"], request), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/v1/live/alerts")
async def live_alerts(request: Request, token: str | None = Query(None),
                      ticket: str | None = Query(None),
                      db: AsyncSession = Depends(get_db)):
    await _sse_ctx(request, token, ticket, db)
    return StreamingResponse(_pubsub_sse([f"{settings.LIVE_PUBSUB_PREFIX}:alerts"], request), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/v1/live/status")
async def live_status(ctx: AuthContext = Depends(get_current_user)):
    """Capture stats + queue depth + DLQ depth + recent metrics gossip."""
    out: dict = {"capture": {}, "queues": {}, "dlq": {}, "metrics": {}}
    try:
        import redis as _redis
        r = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        for k in r.keys("cipherpost:metrics:*"):
            try:
                v = r.get(k)
                if v:
                    import json as _j
                    out["metrics"][k] = _j.loads(v)
            except Exception:
                pass
        # queue depths + dead-letter depths
        for name, stream in [("sessions", settings.SESSION_STREAM), ("findings", settings.FINDINGS_STREAM), ("alerts", settings.ALERT_STREAM)]:
            try:
                info = r.xinfo_stream(stream)
                out["queues"][name] = int(info.get("length", 0)) if isinstance(info, dict) else 0
            except Exception:
                out["queues"][name] = 0
            try:
                from app.live.streams import dlq_name as _dlq
                dinfo = r.xinfo_stream(_dlq(stream))
                out["dlq"][name] = int(dinfo.get("length", 0)) if isinstance(dinfo, dict) else 0
            except Exception:
                out["dlq"][name] = 0
    except Exception as e:
        out["error"] = str(e)
    return out

@app.get("/api/v1/agents")
async def list_agents(ctx: AuthContext = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    """Capture agents with recent heartbeats (track 3), org-filtered."""
    from app.live.agents import list_agents as _list
    try:
        import redis as _redis
        r = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        user = await db.get(User, ctx.user_id) if ctx.user_id else None
        return {"agents": _list(
            r, org_id=ctx.org_id, single_tenant=settings.SINGLE_TENANT,
            is_platform=bool(user is not None and getattr(user, "is_platform_admin", False)))}
    except Exception as e:
        return {"agents": [], "error": str(e)}


@app.get("/api/v1/sessions")
async def list_sessions(
    protocol: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    page: int | None = Query(None, ge=1),
    per_page: int | None = Query(None, ge=1, le=200),
    since: str | None = Query(None, description="ISO timestamp lower bound"),
    ctx: AuthContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    limit, offset = _paginate(limit, offset, page, per_page)
    q = select(Session).where(Session.org_id == ctx.org_id).order_by(Session.id.desc()).offset(offset).limit(limit)
    # severity filter via join findings
    if severity:
        q = select(Session).join(Finding, Finding.session_id==Session.id).where(Finding.severity==Severity(severity), Session.org_id == ctx.org_id).order_by(Session.risk_score.desc().nullslast()).offset(offset).limit(limit)
    if protocol:
        q = q.where(Session.protocol==protocol)
    rows = (await db.execute(q)).scalars().all()
    return [{"id": s.id, "protocol": s.protocol, "five_tuple": s.five_tuple, "tls_version": s.tls_version, "risk_score": s.risk_score, "max_severity": s.max_severity, "is_anomaly": s.is_anomaly, "model_version": s.model_version, "details": s.details} for s in rows]

async def _active_suppressions(db: AsyncSession, org_id: str) -> list:
    """Load active (approved, unexpired) suppressions for an org."""
    from datetime import datetime, timezone
    from app.models.entities import Suppression
    from app.proactive.suppressions import filter_active
    rows = (await db.execute(
        select(Suppression).where(Suppression.org_id == org_id,
                                  Suppression.status == "approved"))).scalars().all()
    return filter_active(rows, datetime.now(timezone.utc))


@app.get("/api/v1/findings")
async def list_findings(
    severity: str | None = Query(None),
    protocol: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    page: int | None = Query(None, ge=1),
    per_page: int | None = Query(None, ge=1, le=200),
    ctx: AuthContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    limit, offset = _paginate(limit, offset, page, per_page)
    q = select(Finding).join(Session, Finding.session_id==Session.id).where(Session.org_id == ctx.org_id).order_by(Finding.severity.desc()).offset(offset).limit(limit)
    if severity:
        q = q.where(Finding.severity==Severity(severity))
    if protocol:
        q = q.where(Session.protocol==protocol)
    rows = (await db.execute(q)).scalars().all()
    from app.proactive.compliance import compliance_for
    from app.proactive.suppressions import match_suppression
    sups = await _active_suppressions(db, ctx.org_id)
    # five_tuples for suppression scope matching (avoid lazy loads)
    sess_ids = list({f.session_id for f in rows})
    ft_map: dict[str, str] = {}
    if sess_ids:
        srows = (await db.execute(
            select(Session.id, Session.five_tuple).where(Session.id.in_(sess_ids)))).all()
        ft_map = {r[0]: r[1] for r in srows}
    out = []
    for f in rows:
        m = match_suppression(f.rule_id,
                              {"five_tuple": ft_map.get(f.session_id, "")},
                              sups)
        out.append({"id": f.id, "session_id": f.session_id, "rule_id": f.rule_id,
                    "severity": f.severity.value, "title": f.title,
                    "description": f.description, "compliance": compliance_for(f.rule_id),
                    "suppressed": m is not None,
                    "suppression_id": getattr(m, "id", None)})
    return out

@app.get("/api/v1/alerts")
async def list_alerts(limit: int = Query(50, ge=1, le=200),
                      ctx: AuthContext = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    try:
        rows = (await db.execute(text("SELECT id, severity, title, five_tuple, payload FROM alerts WHERE org_id = :org ORDER BY ts DESC LIMIT :lim"), {"lim": limit, "org": ctx.org_id})).all()
        return [{"id": r[0], "severity": r[1], "title": r[2], "five_tuple": r[3], "payload": r[4]} for r in rows]
    except Exception:
        return []

@app.get("/api/v1/alerts/config")
async def get_alert_config(ctx: AuthContext = Depends(require_roles("analyst"))):
    from app.live.alerts import load_channels
    from pathlib import Path
    p = Path(settings.ALERT_CHANNEL_CONFIG_PATH)
    cfg = {}
    if p.exists():
        try:
            cfg = _json.loads(p.read_text())
        except Exception:
            pass
    return {"config": cfg, "env": {"webhook": bool(settings.ALERT_WEBHOOK_URL), "slack": bool(settings.ALERT_SLACK_URL), "syslog": bool(settings.ALERT_CEF_SYSLOG_HOST)}}

@app.post("/api/v1/alerts/config")
async def set_alert_config(cfg: dict,
                           ctx: AuthContext = Depends(require_roles("admin")),
                           db: AsyncSession = Depends(get_db)):
    from app.live.alerts import save_channel_config
    save_channel_config(cfg)
    await log_audit(db, ctx.org_id, ctx.email, "alertconfig.update", "channels",
                    {k: ("***" if "url" in k or "token" in k else v)
                     for k, v in cfg.items()})
    return {"status": "saved", "config": cfg}

@app.get("/api/v1/fleet/trend")
async def fleet_trend(days: int = Query(7, ge=1, le=90),
                      ctx: AuthContext = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    """Posture trend bucketed by hour from live sessions."""
    try:
        # use Session.id ordering as proxy for time if no timestamp; fallback to details->live_ts
        rows = (await db.execute(select(Session.risk_score, Session.details).where(Session.org_id == ctx.org_id))).all()
        # simple bucket: average posture per session index bucket
        scores = [r[0] for r in rows if r[0] is not None]
        if not scores:
            return {"points": []}
        # bucket by 10
        bucket = max(1, len(scores)//20)
        points = []
        for i in range(0, len(scores), bucket):
            chunk = scores[i:i+bucket]
            points.append({"x": i, "y": round(sum(chunk)/len(chunk),1)})
        return {"points": points, "total": len(scores)}
    except Exception as e:
        return {"points": [], "error": str(e)}


@app.get("/api/v1/certs")
async def list_certs(limit: int = Query(100, ge=1, le=500),
                     ctx: AuthContext = Depends(get_current_user),
                     db: AsyncSession = Depends(get_db)):
    """Certificate inventory (track 2): every distinct leaf cert observed."""
    from app.models.entities import TrackedCert
    q = select(TrackedCert)
    if ctx.org_id:
        q = q.where((TrackedCert.org_id == ctx.org_id) | (TrackedCert.org_id.is_(None)))
    q = q.order_by(TrackedCert.last_seen.desc()).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [{"fingerprint": r.fingerprint[:16] + "…", "subject_cn": r.subject_cn,
             "issuer_cn": r.issuer_cn, "sans": r.sans,
             "not_after": r.not_after.isoformat() if r.not_after else None,
             "pubkey": f"{r.pubkey_alg} {r.pubkey_bits or ''}".strip(),
             "self_signed": r.is_self_signed, "chain_result": r.chain_result,
             "seen_count": r.seen_count,
             "last_seen": r.last_seen.isoformat() if r.last_seen else None}
            for r in rows]


@app.get("/api/v1/certs/expiring")
async def certs_expiring(days: int = Query(30, ge=1, le=365),
                         ctx: AuthContext = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    """Proactive expiry forecast: certs expiring within `days` (or expired)."""
    from datetime import datetime, timezone
    from app.models.entities import TrackedCert
    horizon = datetime.now(timezone.utc) + __import__("datetime").timedelta(days=days)
    q = select(TrackedCert).where(TrackedCert.not_after.is_not(None),
                                  TrackedCert.not_after <= horizon)
    if ctx.org_id:
        q = q.where((TrackedCert.org_id == ctx.org_id) | (TrackedCert.org_id.is_(None)))
    rows = (await db.execute(q.order_by(TrackedCert.not_after.asc()))).scalars().all()
    now = datetime.now(timezone.utc)

    def _days_remaining(na):
        if not na:
            return None
        if na.tzinfo is None:
            na = na.replace(tzinfo=timezone.utc)
        return (na - now).days

    def _is_expired(na):
        if not na:
            return False
        if na.tzinfo is None:
            na = na.replace(tzinfo=timezone.utc)
        return na < now

    return [{"fingerprint": r.fingerprint[:16] + "…", "subject_cn": r.subject_cn,
             "not_after": r.not_after.isoformat() if r.not_after else None,
             "days_remaining": _days_remaining(r.not_after),
             "expired": _is_expired(r.not_after),
             "seen_count": r.seen_count}
            for r in rows]


@app.get("/api/v1/compliance/summary")
async def compliance_summary(framework: str | None = Query(None),
                             include_suppressed: bool = Query(False),
                             ctx: AuthContext = Depends(get_current_user),
                             db: AsyncSession = Depends(get_db)):
    """Findings grouped by compliance control (track 2).

    Suppressed findings are excluded by default and counted separately as
    "accepted risk" (pass include_suppressed=true to include them normally).
    """
    from app.proactive.compliance import summary_for_findings, FRAMEWORKS
    if framework and framework not in FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework. Choose from {sorted(FRAMEWORKS)}")
    q = select(Finding.rule_id, Finding.severity, Session.five_tuple).join(
        Session, Finding.session_id == Session.id).where(Session.org_id == ctx.org_id)
    rows = (await db.execute(q)).all()
    from app.proactive.suppressions import match_suppression
    sups = await _active_suppressions(db, ctx.org_id)
    live, accepted = [], 0
    for rule_id, sev, ft in rows:
        m = match_suppression(rule_id, {"five_tuple": ft or ""}, sups)
        if m is not None and not include_suppressed:
            accepted += 1
            continue
        live.append({"rule_id": rule_id,
                     "severity": sev.value if hasattr(sev, "value") else str(sev)})
    out = summary_for_findings(live, framework)
    out["suppressed_accepted_risk"] = accepted
    return out


@app.get("/api/v1/domains/{domain}/transport-security")
async def domain_transport_security(domain: str, refresh: bool = Query(False),
                                    ctx: AuthContext = Depends(get_current_user)):
    """MTA-STS/DANE posture for a domain (phase 2: real dnspython checks).

    Backward compatible with the Phase 1 stub contract (same top-level keys);
    `status` is now one of ok/not-published/misconfigured/dns-error/
    dnssec-failed. Pass refresh=true to bypass the TTL cache (on-demand
    re-check); periodic re-checks run via TRANSPORT_RECHECK_INTERVAL_SECONDS.
    """
    from app.proactive.mta_sts import check_domain
    return check_domain(domain, refresh=refresh)


# --- mail flows (phase 2 task 6: per-flow posture) ----------------------------

def _flow_to_dict(f) -> dict:
    total = f.total_sessions or 0
    enc = f.encrypted_sessions or 0
    return {"id": f.id, "client": f.client_host, "server": f.server_host,
            "protocol": f.protocol, "port": f.port,
            "total_sessions": total, "encrypted_sessions": enc,
            "plaintext_sessions": f.plaintext_sessions or 0,
            "encrypted_share": round(enc / total, 3) if total else None,
            "versions": f.versions or {}, "ciphers": f.ciphers or {},
            "best_version": f.best_version,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None}


@app.get("/api/v1/flows")
async def list_flows(unencrypted_within_days: int | None = Query(None, ge=1, le=90),
                     limit: int = Query(100, ge=1, le=500),
                     page: int | None = Query(None, ge=1),
                     per_page: int | None = Query(None, ge=1, le=500),
                     ctx: AuthContext = Depends(get_current_user),
                     db: AsyncSession = Depends(get_db)):
    """Mail flows answering: which flows sent mail unencrypted recently?

    Pass unencrypted_within_days=N to list only flows with plaintext sessions
    seen in the last N days (default listing returns all, worst first).
    """
    from datetime import datetime, timezone, timedelta
    from app.models.entities import MailFlow
    limit, _ = _paginate(limit, 0, page, per_page, maximum=500)
    q = select(MailFlow).where(MailFlow.org_id == ctx.org_id)
    if unencrypted_within_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=unencrypted_within_days)
        q = q.where(MailFlow.plaintext_sessions > 0, MailFlow.last_seen >= cutoff)
    q = q.order_by(MailFlow.plaintext_sessions.desc()).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [_flow_to_dict(f) for f in rows]


@app.get("/api/v1/flows/{flow_id}/history")
async def flow_history(flow_id: str, days: int = Query(30, ge=1, le=90),
                       format: str | None = Query(None),
                       ctx: AuthContext = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    """Per-flow session history over time; format=csv exports unencrypted answers."""
    from datetime import datetime, timezone, timedelta
    from app.models.entities import MailFlow
    flow = await db.get(MailFlow, flow_id)
    if flow is None or flow.org_id != ctx.org_id:
        raise HTTPException(404, "Flow not found")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(Session.five_tuple, Session.tls_version, Session.negotiated_cipher,
               Session.created_at).where(Session.org_id == ctx.org_id)
    rows = (await db.execute(q)).all()
    points = []
    for ft, tls_v, cipher, created in rows:
        if not created:
            continue
        aware = created if getattr(created, "tzinfo", None) else created.replace(tzinfo=timezone.utc)
        if aware < cutoff:
            continue
        # directional pair match for this flow
        if flow.client_host not in (ft or "") or flow.server_host not in (ft or ""):
            continue
        points.append({"tls_version": tls_v, "cipher": cipher,
                       "at": created.isoformat()})
    out = {"flow": _flow_to_dict(flow), "sessions_sampled": len(points),
           "history": sorted(points, key=lambda p: p["at"])}
    if format == "csv":
        import csv as _csv
        import io as _io
        buf = _io.StringIO()
        w = _csv.writer(buf)
        w.writerow(["flow_id", "client", "server", "protocol", "port",
                    "at", "tls_version", "cipher"])
        for p in out["history"]:
            w.writerow([flow.id, flow.client_host, flow.server_host,
                        flow.protocol, flow.port, p["at"],
                        p["tls_version"], p["cipher"]])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition":
                                 f"attachment; filename=flow-{flow.id}.csv"})
    return out


@app.get("/api/v1/ml/versions")
async def ml_versions(ctx: AuthContext = Depends(get_current_user)):
    """Model registry: which versions scored what (track 5)."""
    from app.ml.registry import current_version, history
    return {"current": current_version(), "history": history()}


@app.get("/api/v1/ml/drift")
async def ml_drift(ctx: AuthContext = Depends(require_roles("analyst"))):
    """Rolling-baseline drift check: recent-24h vs prior-6d feature means (org-scoped)."""
    from app.live.baseline import drift_from_db
    return drift_from_db(org_id=ctx.org_id)


@app.get("/api/v1/ml/disagreement")
async def ml_disagreement(ctx: AuthContext = Depends(require_roles("analyst"))):
    """Periodic rule-vs-ML agreement report computed from stored sessions."""
    import sys
    sys.path.insert(0, "scripts")
    from ml_disagreement_report import build_report
    from app.core.config import settings as _s
    rows_report = build_report(org_id=ctx.org_id)
    # Org-scoped: each org sees only its own sessions (fail closed on org).
    return rows_report


@app.get("/api/v1/stats")
async def stats(ctx: AuthContext = Depends(get_current_user),
                db: AsyncSession = Depends(get_db)):
    """Aggregate stats across all jobs (for monitoring)."""
    jobs_res = await db.execute(select(AnalysisJob.id, AnalysisJob.status).where(AnalysisJob.org_id == ctx.org_id))
    rows = jobs_res.all()
    status_counts = {}
    for _, status in rows:
        status_counts[status.value] = status_counts.get(status.value, 0) + 1
    return {
        "total_jobs": len(rows),
        "status_counts": status_counts,
        "version": settings.APP_VERSION,
    }


@app.post("/api/v1/upload", response_model=dict)
async def upload_pcap(
    file: UploadFile = File(...),
    ctx: AuthContext = Depends(require_roles("analyst")),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".pcap"):
        raise HTTPException(400, "Only .pcap files are accepted")
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")

    job_id = uuid.uuid4().hex[:64]
    pcap_path = settings.UPLOAD_DIR / f"{job_id}.pcap"
    with open(pcap_path, "wb") as f:
        f.write(content)

    job = AnalysisJob(
        id=job_id,
        filename=file.filename,
        pcap_path=str(pcap_path),
        status=JobStatus.PENDING,
        file_size=len(content),
        org_id=ctx.org_id,
    )
    db.add(job)
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "pcap.upload", file.filename,
                    {"job_id": job_id, "bytes": len(content)})

    # Dispatch Celery task
    from app.services.tasks import process_analysis_job
    process_analysis_job.delay(job_id)

    return {"job_id": job_id, "status": "pending", "filename": file.filename}


async def _get_org_job(job_id: str, ctx: AuthContext, db: AsyncSession):
    job = await db.get(AnalysisJob, job_id)
    if not job or (job.org_id is not None and job.org_id != ctx.org_id):
        raise HTTPException(404, "Job not found")
    return job


def _paginate(limit: int, offset: int, page: int | None,
               per_page: int | None, maximum: int = 200) -> tuple[int, int]:
    """Canonical pagination: limit/offset, with page/per_page aliases.

    page is 1-based; per_page clamps like limit. Explicit offset wins over page.
    """
    maximum = max(1, int(maximum))
    limit = max(1, min(int(limit), maximum))
    if per_page is not None:
        limit = max(1, min(int(per_page), maximum))
    if offset:
        return limit, max(0, int(offset))
    if page is not None:
        return limit, max(0, (max(1, int(page)) - 1) * limit)
    return limit, 0


@app.get("/api/v1/jobs")
async def list_jobs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    page: int | None = Query(None, ge=1),
    per_page: int | None = Query(None, ge=1, le=200),
    ctx: AuthContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    limit, offset = _paginate(limit, offset, page, per_page)
    q = select(AnalysisJob).where(AnalysisJob.org_id == ctx.org_id).order_by(AnalysisJob.created_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": j.id, "filename": j.filename, "status": j.status.value,
            "progress": j.progress, "file_size": j.file_size,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        }
        for j in rows
    ]


@app.get("/api/v1/jobs/{job_id}")
async def get_job(job_id: str,
                  ctx: AuthContext = Depends(get_current_user),
                  db: AsyncSession = Depends(get_db)):
    job = await _get_org_job(job_id, ctx, db)
    return {
        "id": job.id, "filename": job.filename, "status": job.status.value,
        "progress": job.progress, "message": job.message, "error": job.error,
        "file_size": job.file_size, "legal_hold": bool(getattr(job, "legal_hold", False)),
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@app.post("/api/v1/jobs/{job_id}/legal-hold")
async def set_job_hold(job_id: str, body: dict,
                       ctx: AuthContext = Depends(require_roles("analyst")),
                       db: AsyncSession = Depends(get_db)):
    """Legal hold: hold=true exempts the job (and its sessions) from retention."""
    job = await _get_org_job(job_id, ctx, db)
    job.legal_hold = bool(body.get("hold", True))
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "job.legal_hold", job_id,
                    {"hold": job.legal_hold})
    return {"id": job.id, "legal_hold": job.legal_hold}


@app.post("/api/v1/findings/{finding_id}/legal-hold")
async def set_finding_hold(finding_id: int, body: dict,
                           ctx: AuthContext = Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
    from app.models.entities import Finding as _F
    f = await db.get(_F, finding_id)
    if f is None:
        raise HTTPException(404, "Finding not found")
    sess = await db.get(Session, f.session_id)
    if sess is not None and sess.org_id != ctx.org_id:
        raise HTTPException(404, "Finding not found")
    if ctx.role not in ("admin", "analyst"):
        raise HTTPException(403, "Analysts and admins only")
    f.legal_hold = bool(body.get("hold", True))
    await db.commit()
    await log_audit(db, ctx.org_id, ctx.email, "finding.legal_hold",
                    str(finding_id), {"hold": f.legal_hold})
    return {"id": f.id, "legal_hold": f.legal_hold}


@app.get("/api/v1/jobs/{job_id}/sessions")
async def get_sessions(job_id: str,
                       ctx: AuthContext = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    await _get_org_job(job_id, ctx, db)
    q = select(Session).where(Session.job_id == job_id).order_by(Session.risk_score.desc().nullslast())
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": s.id, "protocol": s.protocol, "five_tuple": s.five_tuple,
            "tls_version": s.tls_version, "negotiated_cipher": s.negotiated_cipher,
            "cipher_strength": s.cipher_strength, "pfs_supported": s.pfs_supported,
            "cert_chain_valid": s.cert_chain_valid, "cert_age_days": s.cert_age_days,
            "is_starttls": s.is_starttls, "is_anomaly": s.is_anomaly,
            "risk_score": s.risk_score, "max_severity": s.max_severity,
            "overall_finding_count": s.overall_finding_count,
            "model_version": s.model_version,
            "details": s.details,
        }
        for s in rows
    ]


@app.get("/api/v1/jobs/{job_id}/findings")
async def get_findings(
    job_id: str,
    severity: Optional[str] = Query(None),
    ctx: AuthContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _get_org_job(job_id, ctx, db)
    q = select(Finding).join(Session).where(Session.job_id == job_id)
    if severity:
        q = q.where(Finding.severity == Severity(severity))
    q = q.order_by(
        Finding.severity.desc(),
        Session.risk_score.desc().nullslast(),
    )
    rows = (await db.execute(q)).scalars().all()
    from app.proactive.compliance import compliance_for as _cf
    return [
        {
            "id": f.id, "session_id": f.session_id,
            "rule_id": f.rule_id, "rule_name": f.rule_name,
            "severity": f.severity.value, "title": f.title,
            "description": f.description, "reference": f.reference,
            "kind": f.kind, "evidence": f.evidence,
            "compliance": _cf(f.rule_id),
        }
        for f in rows
    ]


@app.get("/api/v1/jobs/{job_id}/shap")
async def get_shap(job_id: str,
                   ctx: AuthContext = Depends(get_current_user),
                   db: AsyncSession = Depends(get_db)):
    await _get_org_job(job_id, ctx, db)
    q = (
        select(ShaPRow)
        .join(Session)
        .where(Session.job_id == job_id)
        .order_by(func.abs(ShaPRow.impact).desc())
    )
    rows = (await db.execute(q)).scalars().all()
    return [
        {"session_id": r.session_id, "feature": r.feature,
         "value": r.value, "impact": r.impact, "method": r.method}
        for r in rows
    ]


@app.get("/api/v1/jobs/{job_id}/fleet")
async def get_fleet_summary(job_id: str,
                            ctx: AuthContext = Depends(get_current_user),
                            db: AsyncSession = Depends(get_db)):
    await _get_org_job(job_id, ctx, db)
    sessions_q = select(Session).where(Session.job_id == job_id)
    sessions = (await db.execute(sessions_q)).scalars().all()
    if not sessions:
        return {"total_sessions": 0, "fleet_score": 0, "severity_distribution": {}}
    total = len(sessions)
    avg_score = sum(s.risk_score or 0 for s in sessions) / total
    sev_dist = {}
    for s in sessions:
        sev_dist[s.max_severity or "none"] = sev_dist.get(s.max_severity or "none", 0) + 1
    return {
        "total_sessions": total,
        "fleet_score": round(avg_score, 1),
        "anomaly_count": sum(1 for s in sessions if s.is_anomaly),
        "severity_distribution": sev_dist,
        "sessions": [
            {"five_tuple": s.five_tuple, "protocol": s.protocol,
             "risk_score": s.risk_score, "is_anomaly": s.is_anomaly,
             "max_severity": s.max_severity, "tls_version": s.tls_version}
            for s in sessions
        ],
    }


@app.get("/api/v1/jobs/{job_id}/report.{fmt}")
async def get_report(job_id: str, fmt: str,
                     ctx: AuthContext = Depends(get_current_user),
                     db: AsyncSession = Depends(get_db)):
    if fmt not in ("json", "html", "pdf"):
        raise HTTPException(400, "Format must be json, html, or pdf")
    job = await _get_org_job(job_id, ctx, db)
    if job.status != JobStatus.COMPLETED:
        raise HTTPException(409, "Job not yet completed")
    await log_audit(db, ctx.org_id, ctx.email, "report.export", job.filename,
                    {"job_id": job_id, "format": fmt})

    report_path = settings.REPORTS_DIR / f"{job_id}.{fmt}"
    if report_path.exists():
        if fmt == "html":
            return HTMLResponse(report_path.read_text())
        elif fmt == "json":
            return JSONResponse(report_path.read_text(), media_type="application/json")
        else:
            return Response(
                report_path.read_bytes(),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=cipherpost-{job_id}.pdf"},
            )

    # Generate on-the-fly if missing
    analyses, scores = await _load_analysis_from_db(job_id, db)
    from app.reporting.generator import generate_json, generate_html, generate_pdf
    if fmt == "json":
        content = generate_json(analyses, scores, job.filename)
        report_path.write_text(content)
        return JSONResponse(content)
    elif fmt == "html":
        content = generate_html(analyses, scores, job.filename)
        report_path.write_text(content)
        return HTMLResponse(content)
    else:
        html = generate_html(analyses, scores, job.filename)
        pdf_path = generate_pdf(html, str(report_path))
        if pdf_path and Path(pdf_path).exists():
            return Response(Path(pdf_path).read_bytes(), media_type="application/pdf")
        raise HTTPException(500, "PDF generation failed (WeasyPrint unavailable)")


async def _load_analysis_from_db(job_id: str, db):
    """Load SessionAnalysis objects from DB for report generation."""
    from app.parsing.rules import SessionAnalysis, Finding as RuleFinding
    from app.ml.ml_engine import ScoringResult, RiskScore, AnomalyResult

    sessions_q = select(Session).where(Session.job_id == job_id)
    sessions = (await db.execute(sessions_q)).scalars().all()
    analyses, scores = [], []
    for s in sessions:
        findings_q = select(Finding).where(Finding.session_id == s.id)
        findings = (await db.execute(findings_q)).scalars().all()
        sa = SessionAnalysis(
            session_id=s.id, protocol=s.protocol, five_tuple=s.five_tuple,
            is_starttls=s.is_starttls,
        )
        sa.tls_version = _version_hex(s.tls_version) if s.tls_version else None
        sa.cipher = s.negotiated_cipher
        sa.cipher_strength = s.cipher_strength
        sa.chain_result = "ok" if s.cert_chain_valid else "untrusted"
        sa.findings = [
            RuleFinding(
                rule_id=f.rule_id, rule_name=f.rule_name, severity=f.severity.value,
                title=f.title, description=f.description, reference=f.reference,
            )
            for f in findings
        ]
        analyses.append(sa)
        scores.append(ScoringResult(
            risk=RiskScore(probability=(s.risk_score or 0)/100, posture_score=s.risk_score or 0,
                           class_label="at-risk" if (s.risk_score or 0) >= 50 else "healthy"),
            anomaly=AnomalyResult(is_anomaly=s.is_anomaly, anomaly_score=-1.0),
        ))
    return analyses, scores


def _version_hex(ver_str: str | None) -> int | None:
    if not ver_str:
        return None
    mapping = {"SSLv3": 0x0300, "TLS 1.0": 0x0301, "TLS 1.1": 0x0302, "TLS 1.2": 0x0303, "TLS 1.3": 0x0304}
    return mapping.get(ver_str)
