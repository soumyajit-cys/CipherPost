"""Phase 1 test defaults: run the suite with strong secrets.

Production is the default ENV and refuses weak defaults, so unit tests must
not depend on the insecure placeholders. We inject strong test-only values
via env vars BEFORE app.core.config is imported (conftest loads first).
Real deployments must set their own CIPHERPOST_JWT_SECRET / ADMIN_PASSWORD.
"""
import os

os.environ.setdefault("CIPHERPOST_ENV", "production")
os.environ.setdefault(
    "CIPHERPOST_JWT_SECRET",
    "test-only-jwt-secret-0123456789abcdef-0123456789abcdef",
)
os.environ.setdefault("CIPHERPOST_ADMIN_PASSWORD", "test-admin-password-123")
