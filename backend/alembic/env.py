"""Alembic environment: sync migrations against SQLAlchemy models.

Uses CIPHERPOST_DATABASE_URL_SYNC (psycopg2) when set, else DATABASE_URL with
async driver swapped for sync. Falls back to local Postgres for CI.
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

# Ensure `app.*` imports work when alembic runs from repo root or backend/.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

config = context.config
if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass

from app.core.config import settings  # noqa: E402
from app.core.database import Base  # noqa: E402
import app.models.entities  # noqa: E402,F401 ensure metadata registered

target_metadata = Base.metadata


def _sync_url() -> str:
    url = os.environ.get("CIPHERPOST_DATABASE_URL_SYNC") or getattr(
        settings, "DATABASE_URL_SYNC", ""
    )
    if not url:
        # Derive sync URL from async URL for local runs.
        async_url = os.environ.get("CIPHERPOST_DATABASE_URL") or settings.DATABASE_URL
        url = async_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_sync_url(), target_metadata=target_metadata,
                      literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_sync_url(), future=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
