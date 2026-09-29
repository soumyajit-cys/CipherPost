"""Health aggregation (Phase 2 Task 7).

collect_health(): DB reachable, Redis reachable, consumer lag per stream,
dead-letter depth, capture drop counters (from metrics gossip), migrations
at head. Every check is best-effort with a short timeout; failures degrade
the status instead of raising.

readiness(): strict subset for Kubernetes (DB + Redis + migrations).
"""
from __future__ import annotations

import asyncio
import time


async def _db_ok(timeout: float = 2.0) -> tuple[bool, str]:
    """Check the configured DATABASE_URL (fresh short-lived engine, so health
    honors current settings and never borrows the app pool)."""
    try:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine
        from app.core.config import settings as _s
        eng = create_async_engine(_s.DATABASE_URL, poolclass=None)
        try:
            async with eng.connect() as conn:
                await asyncio.wait_for(conn.execute(text("SELECT 1")), timeout)
        finally:
            await eng.dispose()
        return True, ""
    except Exception as e:
        return False, str(e)[:200]


def _redis_info(timeout: float = 2.0) -> tuple[bool, dict]:
    try:
        import redis as _redis
        from app.core.config import settings as _s
        r = _redis.Redis.from_url(_s.REDIS_URL, decode_responses=True,
                                  socket_connect_timeout=timeout,
                                  socket_timeout=timeout)
        r.ping()
        info: dict = {"reachable": True}
        for name, stream in (("sessions", _s.SESSION_STREAM),
                             ("findings", _s.FINDINGS_STREAM),
                             ("alerts", _s.ALERT_STREAM)):
            try:
                length = r.xlen(stream)
            except Exception:
                length = 0
            try:
                from app.live.streams import dlq_name as _dlq
                dlq = r.xlen(_dlq(stream))
            except Exception:
                dlq = 0
            pending = 0
            try:
                for g in r.xinfo_groups(stream):
                    pending += int(g.get("pending", 0) or 0)
            except Exception:
                pass
            info[name] = {"lag": int(length or 0), "pending": pending,
                          "dlq_depth": int(dlq or 0)}
        return True, info
    except Exception as e:
        return False, {"reachable": False, "error": str(e)[:200]}


def _migrations_ok() -> tuple[bool, str]:
    try:
        from alembic.config import Config as _Cfg
        from alembic.script import ScriptDirectory as _SD
        import os as _os
        root = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "..", ".."))
        ini = _os.path.join(root, "backend", "alembic.ini")
        if not _os.path.exists(ini):
            ini = _os.path.abspath("backend/alembic.ini")
        cfg = _Cfg(ini)
        script = _SD.from_config(cfg)
        heads = set(script.get_heads())
        try:
            from alembic.runtime.migration import MigrationContext as _MC
            from sqlalchemy import create_engine as _ce
            from app.core.config import settings as _s
            url = getattr(_s, "DATABASE_URL_SYNC", "")
            if not url or url.startswith("sqlite"):
                return True, "sqlite (migrations n/a)"
            eng = _ce(url)
            with eng.connect() as conn:
                ctx = _MC.configure(conn)
                current = set(ctx.get_current_heads() or [])
            if current == heads:
                return True, ""
            return False, f"at {sorted(current)} want {sorted(heads)}"
        except Exception as e:
            return False, str(e)[:200]
    except Exception as e:
        return False, str(e)[:200]


def _gossip_drops() -> dict:
    try:
        import redis as _redis
        import json as _j
        from app.core.config import settings as _s
        r = _redis.Redis.from_url(_s.REDIS_URL, decode_responses=True,
                                  socket_connect_timeout=2, socket_timeout=2)
        drops: dict = {}
        for k in r.keys("cipherpost:metrics:*"):
            try:
                vals = _j.loads(r.get(k) or "{}")
                for m, v in (vals or {}).items():
                    if "dropped" in m and isinstance(v, (int, float)):
                        drops[m] = drops.get(m, 0) + v
            except Exception:
                pass
        return drops
    except Exception:
        return {}


async def collect_health() -> dict:
    from app.core.config import settings as _s
    started = time.time()
    (db_ok, db_err), (redis_ok, redis_info), (mig_ok, mig_err) = await asyncio.gather(
        _db_ok(), asyncio.to_thread(_redis_info), asyncio.to_thread(_migrations_ok))
    drops = await asyncio.to_thread(_gossip_drops)
    problems: list[str] = []
    if not db_ok:
        problems.append(f"db: {db_err}")
    if not redis_ok:
        problems.append(f"redis: {redis_info.get('error', 'down')}")
    if not mig_ok:
        problems.append(f"migrations: {mig_err}")
    total_dlq = sum((v.get("dlq_depth", 0) if isinstance(v, dict) else 0)
                    for v in redis_info.values() if isinstance(v, dict))
    if total_dlq > 0:
        problems.append(f"dead-letter depth {total_dlq}")
    status = "ok" if not problems else ("down" if (not db_ok or not redis_ok) else "degraded")
    return {"status": status, "version": _s.APP_VERSION,
            "db_ok": db_ok, "redis_ok": redis_ok, "migrations_ok": mig_ok,
            "streams": {k: v for k, v in redis_info.items() if k != "reachable"
                        and "error" not in str(v)},
            "drops": drops,
            "problems": problems,
            "elapsed_ms": round((time.time() - started) * 1000, 1)}


async def readiness() -> tuple[bool, dict]:
    from app.core.config import settings as _s
    (db_ok, db_err), (redis_ok, redis_info), (mig_ok, mig_err) = await asyncio.gather(
        _db_ok(), asyncio.to_thread(_redis_info), asyncio.to_thread(_migrations_ok))
    ready = bool(db_ok and redis_ok and mig_ok)
    return ready, {"version": _s.APP_VERSION, "db_ok": db_ok,
                   "redis_ok": redis_ok, "migrations_ok": mig_ok,
                   "db_error": db_err, "redis_error": redis_info.get("error", ""),
                   "migration_error": mig_err}
