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
