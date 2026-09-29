"""cipherpost-migrate: upgrade Postgres to head via Alembic.

Usage:
  python -m app.migrate              # upgrade to head
  cipherpost-migrate                 # same (console entrypoint if installed)
  python -m app.migrate check        # fail (exit 2) if models drift from migrations

Honest behavior:
- Requires a Postgres SYNC URL (CIPHERPOST_DATABASE_URL_SYNC or derived).
- Refuses to run against SQLite (tests use create_all directly).
- Logs clearly; exits non-zero on failure so compose/k8s init can gate API start.
"""
from __future__ import annotations

import os
import sys


def _sync_url() -> str:
    url = os.environ.get("CIPHERPOST_DATABASE_URL_SYNC", "")
    if not url:
        # Fall back to config (reads .env / env prefix).
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        from app.core.config import settings as _s
        url = getattr(_s, "DATABASE_URL_SYNC", "") or ""
    if not url:
        raise RuntimeError("CIPHERPOST_DATABASE_URL_SYNC is not set")
    if url.startswith("sqlite"):
        raise RuntimeError("refusing to run Alembic against SQLite (use create_all in tests)")
    return url


def upgrade_to_head() -> None:
    from alembic.config import Config as _Cfg
    from alembic import command as _cmd
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ini = os.path.join(root, "backend", "alembic.ini")
    if not os.path.exists(ini):
        ini = os.path.join(os.getcwd(), "backend", "alembic.ini")
    cfg = _Cfg(ini)
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(ini), "alembic")
                        if os.path.basename(ini) == "alembic.ini" else "backend/alembic")
    # Ensure env.py sees the right DB.
    os.environ["CIPHERPOST_DATABASE_URL_SYNC"] = _sync_url()
    _cmd.upgrade(cfg, "head")
    print("cipherpost-migrate: upgraded to head")


def check_no_drift() -> None:
    from alembic.config import Config as _Cfg
    from alembic import command as _cmd
    from alembic.runtime import migration as _mig
    from alembic.autogenerate import compare as _compare  # noqa: F401 (ensures plugin)
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ini = os.path.join(root, "backend", "alembic.ini")
    cfg = _Cfg(ini)
    # Use `alembic check` semantics via command API if available, else manual.
    try:
        _cmd.check(cfg)  # type: ignore[attr-defined]
        print("cipherpost-migrate: no drift")
    except AttributeError:
        # Older Alembic without `check`: fall back to upgrade --sql dry run? Fail clearly.
        raise RuntimeError("installed Alembic lacks `check`; upgrade Alembic to use drift gate")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if argv and argv[0] == "check":
            check_no_drift()
        else:
            upgrade_to_head()
        return 0
    except Exception as e:
        print(f"cipherpost-migrate failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
