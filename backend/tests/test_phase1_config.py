"""Phase 1 Task 1: production startup-refusal cases for secrets."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest

from app.core.config import (
    Settings,
    validate_startup_secrets,
)


def _prod(**over):
    base = dict(
        ENV="production",
        JWT_SECRET="a" * 64,
        ADMIN_PASSWORD="strong-password-123",
    )
    base.update(over)
    return Settings(**base)


def test_production_ok_with_strong_secrets():
    validate_startup_secrets(_prod())


def test_production_refuses_missing_jwt():
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        validate_startup_secrets(_prod(JWT_SECRET=""))


def test_production_refuses_default_jwt():
    for bad in ("change-me-in-production", "CHANGEME-long-random-64-chars-minimum",
                "cipherpost-dev-only-secret"):
        with pytest.raises(RuntimeError, match="JWT_SECRET"):
            validate_startup_secrets(_prod(JWT_SECRET=bad))


def test_production_refuses_short_jwt():
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        validate_startup_secrets(_prod(JWT_SECRET="short-secret"))


def test_production_refuses_default_admin_password():
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
        validate_startup_secrets(_prod(ADMIN_PASSWORD="change-me-on-first-login"))


def test_production_refuses_short_admin_password():
    with pytest.raises(RuntimeError, match="at least 12 characters"):
        validate_startup_secrets(_prod(ADMIN_PASSWORD="short123"))


def test_dev_skips_validation():
    s = Settings(ENV="dev", JWT_SECRET="", ADMIN_PASSWORD="")
    validate_startup_secrets(s)  # must not raise


def test_dev_jwt_is_ephemeral_random(monkeypatch):
    monkeypatch.setenv("CIPHERPOST_ENV", "dev")
    # Re-import settings with dev env
    from app.core import config as cfgmod
    dev_settings = Settings(ENV="dev", JWT_SECRET="", ADMIN_PASSWORD="x")
    monkeypatch.setattr(cfgmod, "settings", dev_settings)
    # Clear cached ephemeral secret if present
    import app.core.auth as authmod
    if hasattr(authmod, "_DEV_EPHEMERAL_SECRET"):
        delattr(authmod, "_DEV_EPHEMERAL_SECRET")
    s1 = authmod._jwt_secret()
    assert len(s1) >= 32
    assert b"cipherpost-dev-only-secret" not in s1
    s2 = authmod._jwt_secret()
    assert s1 == s2  # stable per-process
    if hasattr(authmod, "_DEV_EPHEMERAL_SECRET"):
        delattr(authmod, "_DEV_EPHEMERAL_SECRET")
