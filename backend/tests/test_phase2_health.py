"""Phase 2 Task 7: health endpoints (no real infra required)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio


def test_collect_health_never_raises_without_infra(monkeypatch):
    from app.live import health as h
    # Point at dead ports so every check fails fast.
    from app.core import config as cfg
    monkeypatch.setattr(cfg.settings, "DATABASE_URL",
                        "postgresql+asyncpg://u:p@127.0.0.1:1/db")
    monkeypatch.setattr(cfg.settings, "DATABASE_URL_SYNC",
                        "postgresql+psycopg2://u:p@127.0.0.1:1/db")
    monkeypatch.setattr(cfg.settings, "REDIS_URL", "redis://127.0.0.1:1/0")
    out = asyncio.get_event_loop().run_until_complete(h.collect_health())
    assert out["status"] in ("down", "degraded")
    assert out["db_ok"] is False and out["redis_ok"] is False
    assert out["problems"]
    ready, detail = asyncio.get_event_loop().run_until_complete(h.readiness())
    assert ready is False
    assert detail["db_ok"] is False


def test_liveness_and_ready_routes():
    from fastapi.testclient import TestClient
    from app.api.main import app
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/v1/health/live")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    r = c.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["status"] in ("ok", "degraded", "down")
