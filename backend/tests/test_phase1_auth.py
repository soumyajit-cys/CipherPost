"""Phase 1 Task 2: PyJWT hardening cases."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import base64
import json


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_expired_rejected():
    from app.core.auth import create_access_token, decode_token
    import pytest
    tok = create_access_token("u", "o", "analyst", expires_in=-1)
    with pytest.raises(ValueError, match="expired"):
        decode_token(tok)


def test_tampered_rejected():
    from app.core.auth import create_access_token, decode_token
    import pytest
    tok = create_access_token("user-1", "org-1", "analyst", expires_in=60)
    h, p, s = tok.split(".")
    bad = _b64({"sub": "admin", "org": "org-1", "role": "admin", "iat": 0, "exp": 9999999999})
    with pytest.raises(ValueError):
        decode_token(f"{h}.{bad}.{s}")


def test_alg_none_rejected():
    from app.core.auth import decode_token
    import pytest
    h = _b64({"alg": "none", "typ": "JWT"})
    p = _b64({"sub": "u", "org": "o", "role": "analyst", "iat": 0, "exp": 9999999999})
    with pytest.raises(ValueError):
        decode_token(f"{h}.{p}.")
    # wrong alg (HS512 token presented as HS256) must also fail
    import jwt as pyjwt
    from app.core import config as cfg
    hs512 = pyjwt.encode({"sub": "u", "org": "o", "role": "analyst",
                          "iat": 0, "exp": 9999999999},
                         cfg.settings.JWT_SECRET, algorithm="HS512")
    with pytest.raises(ValueError):
        decode_token(hs512)


def test_roundtrip_claims():
    from app.core.auth import create_access_token, decode_token
    tok = create_access_token("user-1", "org-1", "analyst", expires_in=60)
    claims = decode_token(tok)
    assert claims["sub"] == "user-1"
    assert claims["org"] == "org-1"
    assert claims["role"] == "analyst"


def test_sse_ticket_single_use_and_scope():
    from app.core.auth import create_access_token, create_sse_ticket, consume_sse_ticket
    import pytest
    t1 = create_sse_ticket("u1", "o1", "analyst")
    claims = consume_sse_ticket(t1)
    assert claims["scope"] == "live:read"
    with pytest.raises(ValueError, match="already used"):
        consume_sse_ticket(t1)
    # main token (no scope) must not pass as ticket
    main = create_access_token("u1", "o1", "analyst", expires_in=60)
    with pytest.raises(ValueError):
        consume_sse_ticket(main)


def test_login_lockout_in_memory():
    from app.core.auth import (
        is_login_locked, record_login_failure, record_login_success, _reset_login_state,
    )
    _reset_login_state()
    acct, ip = "login:acct:test-lock@example.com", "login:ip:127.0.0.99"
    assert not is_login_locked(acct, ip)
    for _ in range(5):
        record_login_failure(acct, ip)
    assert is_login_locked(acct, ip)
    record_login_success(acct, ip)
    # account bucket cleared; IP bucket retained (spray protection) but single
    # account lock lifted only after lock expiry — in-memory keeps lock, so
    # assert lock still present for acct (safer default) OR cleared? We clear
    # failures but locks persist until TTL; document behavior:
    assert is_login_locked(acct, ip)
    _reset_login_state()
    assert not is_login_locked(acct, ip)


def test_cors_default_same_origin():
    from app.core.config import Settings
    s = Settings(ENV="production", JWT_SECRET="x" * 40, ADMIN_PASSWORD="strong-pass-123",
                 CORS_ORIGINS="")
    assert s.cors_origins_list() == []
    s2 = Settings(ENV="production", JWT_SECRET="x" * 40, ADMIN_PASSWORD="strong-pass-123",
                  CORS_ORIGINS="https://app.example.com, https://soc.example.com")
    assert s2.cors_origins_list() == ["https://app.example.com", "https://soc.example.com"]
