"""Phase 1 Task 5: migration sanity (no Postgres required)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))


def test_models_include_raw_tables():
    from app.core.database import Base
    import app.models.entities as _e  # noqa: ensure registered
    assert "alerts" in Base.metadata.tables
    assert "baseline_features" in Base.metadata.tables
    assert "organizations" in Base.metadata.tables
    assert "users" in Base.metadata.tables


def test_initial_migration_covers_raw_tables():
    import pathlib
    versions = list(pathlib.Path("backend/alembic/versions").glob("*.py"))
    assert versions, "no migrations found"
    text = "\n".join(p.read_text() for p in versions)
    assert "create_table('alerts'" in text
    assert "create_table('baseline_features'" in text


def test_migrate_entrypoint_exists():
    import app.migrate as m
    assert callable(m.upgrade_to_head)
    assert callable(m.check_no_drift)
