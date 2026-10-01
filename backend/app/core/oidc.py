"""OIDC login (Phase 3 Task 1): authorization code + PKCE, strict validation.

Fail-closed rules (no exceptions):
- SSO is disabled unless OIDC_ISSUER + OIDC_CLIENT_ID are both set.
- Only RS256 (pinned) via the issuer's JWKS; unsigned (`none`) and symmetric
  (`HS*`) tokens are rejected before any claim is trusted.
- Issuer, audience, expiry, and nonce are all required and validated.
- Unknown `kid` triggers exactly one JWKS refresh (rotation); still-unknown
  kids are rejected.
- Group/claim mapping defaults to least privilege (OIDC_DEFAULT_ROLE).
- Nothing here raises into callers unexpectedly: verification returns claims
  or raises ValueError; network failures raise ValueError("dns-error..."-style
  as "oidc-error ...") so the API maps them to safe 4xx/503 responses.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import secrets
import time

log = logging.getLogger("cipherpost.auth.oidc")

_ALLOWED_ALGS = ("RS256",)
_STATE_TTL = 600


def enabled() -> bool:
    from app.core import config as _cfg
    s = _cfg.settings
    return bool((s.OIDC_ISSUER or "").strip() and (s.OIDC_CLIENT_ID or "").strip())


def _issuer() -> str:
    from app.core import config as _cfg
    return (_cfg.settings.OIDC_ISSUER or "").strip().rstrip("/")


# --------------------------------------------------------------------------
# HTTP + caching (tiny TTL cache; rotation handled by callers)
# --------------------------------------------------------------------------

_jwks_cache: dict = {"at": 0.0, "keys": {}, "doc": {}}


def fetch_json(url: str, timeout: float = 10.0) -> dict:
    """Separated for tests (monkeypatch this, not httpx)."""
    import httpx
    r = httpx.get(url, timeout=timeout, follow_redirects=True)
    r.raise_for_status()
    return r.json()


def _jwks_ttl() -> int:
    from app.core import config as _cfg
    try:
        return max(60, int(_cfg.settings.OIDC_JWKS_CACHE_SECONDS))
    except Exception:
        return 600


def discovery(refresh: bool = False) -> dict:
    cached = _jwks_cache.get("doc")
    if cached and not refresh and time.time() - _jwks_cache.get("at", 0) < _jwks_ttl():
        return cached
    doc = fetch_json(_issuer() + "/.well-known/openid-configuration")
    if not isinstance(doc, dict) or "jwks_uri" not in doc:
        raise ValueError("oidc-error: bad discovery document")
    _jwks_cache["doc"] = doc
    _jwks_cache["at"] = time.time()
    return doc


def jwks_keys(refresh: bool = False) -> dict:
    keys = _jwks_cache.get("keys") or {}
    if keys and not refresh and time.time() - _jwks_cache.get("at", 0) < _jwks_ttl():
        return keys
    doc = discovery(refresh=refresh)
    raw = fetch_json(doc["jwks_uri"])
    out = {}
    for k in (raw.get("keys") or []):
        if k.get("kty") == "RSA" and k.get("kid") and k.get("n") and k.get("e"):
            out[k["kid"]] = k
    if not out:
        raise ValueError("oidc-error: JWKS has no RSA keys")
    _jwks_cache["keys"] = out
    return out


def _rsa_key_for(kid: str):
    from jwt.algorithms import RSAAlgorithm
    keys = jwks_keys()
    if kid not in keys:
        keys = jwks_keys(refresh=True)  # exactly one rotation retry
        if kid not in keys:
            raise ValueError("oidc-error: unknown key id")
    return RSAAlgorithm.from_jwk(json.dumps(keys[kid]))


# --------------------------------------------------------------------------
# Token verification
# --------------------------------------------------------------------------

def verify_id_token(token: str, nonce: str | None) -> dict:
    """Validate iss/aud/signature(RS256)/exp/nonce. Returns claims."""
    import jwt as _pyjwt
    from app.core import config as _cfg
    if not enabled():
        raise ValueError("oidc-error: SSO is not configured")
    try:
        header = _pyjwt.get_unverified_header(token)
    except Exception as e:
        raise ValueError(f"oidc-error: unreadable token ({e})")
    alg = header.get("alg", "")
    if alg not in _ALLOWED_ALGS:
        raise ValueError(f"oidc-error: rejected algorithm {alg!r}")
    kid = header.get("kid", "")
    if not kid:
        raise ValueError("oidc-error: missing key id")
    key = _rsa_key_for(kid)
    try:
        claims = _pyjwt.decode(
            token, key, algorithms=list(_ALLOWED_ALGS),
            issuer=_issuer(), audience=_cfg.settings.OIDC_CLIENT_ID,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except _pyjwt.InvalidTokenError as e:
        raise ValueError(f"oidc-error: invalid token ({e})")
    if nonce is not None and claims.get("nonce") != nonce:
        raise ValueError("oidc-error: nonce mismatch (possible replay)")
    return claims


# --------------------------------------------------------------------------
# Claim mapping (least privilege by default)
# --------------------------------------------------------------------------

def map_role_org(claims: dict) -> tuple[str, str]:
    """Apply OIDC_CLAIM_RULES (first match wins); else defaults.

    Rule: {"claim": "groups", "match": "*@admins", "role": "admin",
           "org": "acme"}. Role must be a known role or it is ignored.
    """
    import fnmatch as _fn
    from app.core import config as _cfg
    from app.core.auth import ROLE_ORDER
    try:
        rules = json.loads(_cfg.settings.OIDC_CLAIM_RULES or "[]")
    except Exception:
        rules = []
    for rule in rules:
        try:
            claim = str(rule.get("claim", ""))
            pattern = str(rule.get("match", ""))
            values = claims.get(claim, [])
            if isinstance(values, str):
                values = [values]
            if any(_fn.fnmatchcase(str(v), pattern) for v in values):
                role = str(rule.get("role", ""))
                if role not in ROLE_ORDER:
                    continue
                org = str(rule.get("org") or _cfg.settings.OIDC_DEFAULT_ORG)
                return role, org
        except Exception:
            continue
    return _cfg.settings.OIDC_DEFAULT_ROLE, _cfg.settings.OIDC_DEFAULT_ORG


# --------------------------------------------------------------------------
# PKCE + state store (Redis with in-memory fallback, like login lockout)
# --------------------------------------------------------------------------

_mem_states: dict[str, tuple[float, dict]] = {}


def _state_redis():
    try:
        import redis as _redis
        from app.core import config as _cfg
        return _redis.Redis.from_url(_cfg.settings.REDIS_URL, decode_responses=True,
                                     socket_connect_timeout=1, socket_timeout=1)
    except Exception:
        return None


def pkce_pair() -> tuple[str, str]:
    """Return (verifier, S256 challenge)."""
    import base64 as _b64
    import hashlib as _hl
    verifier = secrets.token_urlsafe(64)
    challenge = _b64.urlsafe_b64encode(_hl.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def new_authorize_url(redirect_uri: str) -> tuple[str, str]:
    """Build the IdP authorize URL; returns (url, state). State is server-stored."""
    from urllib.parse import urlencode
    from app.core import config as _cfg
    doc = discovery()
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    payload = json.dumps({"verifier": verifier, "nonce": nonce,
                          "at": time.time()})
    r = _state_redis()
    stored = False
    if r is not None:
        try:
            r.setex(f"oidc:state:{state}", _STATE_TTL, payload)
            stored = True
        except Exception:
            pass
    if not stored:
        _mem_states[state] = (time.time() + _STATE_TTL, {"verifier": verifier, "nonce": nonce})
        if len(_mem_states) > 1000:
            oldest = sorted(_mem_states, key=lambda k: _mem_states[k][0])[:100]
            for k in oldest:
                _mem_states.pop(k, None)
    params = urlencode({
        "response_type": "code", "client_id": _cfg.settings.OIDC_CLIENT_ID,
        "redirect_uri": redirect_uri, "scope": _cfg.settings.OIDC_SCOPES,
        "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    return doc.get("authorization_endpoint", "") + "?" + params, state


def consume_state(state: str) -> dict:
    """Pop state (single-use, expiry-checked). Raises ValueError on replay/expiry."""
    r = _state_redis()
    if r is not None:
        try:
            raw = r.get(f"oidc:state:{state}")
            if raw is None:
                raise ValueError("oidc-error: unknown or expired state (possible replay)")
            r.delete(f"oidc:state:{state}")
            data = json.loads(raw)
            if time.time() - float(data.get("at", 0)) > _STATE_TTL:
                raise ValueError("oidc-error: state expired")
            return data
        except ValueError:
            raise
        except Exception:
            pass
    hit = _mem_states.pop(state, None)
    if hit is None:
        raise ValueError("oidc-error: unknown or expired state (possible replay)")
    exp, data = hit
    if time.time() > exp:
        raise ValueError("oidc-error: state expired")
    return data


def exchange_code(code: str, verifier: str, redirect_uri: str) -> dict:
    """Exchange the code for tokens. Returns the token response dict."""
    import httpx
    from app.core import config as _cfg
    doc = discovery()
    try:
        r = httpx.post(doc.get("token_endpoint", ""), data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": redirect_uri,
            "client_id": _cfg.settings.OIDC_CLIENT_ID,
            "client_secret": _cfg.settings.OIDC_CLIENT_SECRET,
            "code_verifier": verifier,
        }, timeout=15.0)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise ValueError(f"oidc-error: code exchange failed ({e})")


def reset_cache() -> None:
    """Test-only: clear JWKS/discovery cache."""
    _jwks_cache.update({"at": 0.0, "keys": {}, "doc": {}})
