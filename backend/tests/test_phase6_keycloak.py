"""Item 6: SSO against real Keycloak (slow integration, env-gated).

Runs ONLY when CIPHERPOST_TEST_KEYCLOAK_URL and
CIPHERPOST_TEST_KEYCLOAK_ADMIN_PASSWORD are set (lab Keycloak 26.8.0,
realm cipherpost-test prepared by /tmp/opencode/keycloak/setup_realm.py or
equivalent). Otherwise skipped — never fails closed environments.

Covers against the LIVE IdP: full code+PKCE login for two users,
group-to-role mapping, unknown-kid JWKS refresh (cache cleared to force it),
short-lifetime token expiry rejection, disabled-user rejection, and state
single-use/replay rejection. Realm mutations (lifespan, disabled flag) are
restored in finally blocks.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

pytestmark = pytest.mark.slow

KC_URL = os.environ.get("CIPHERPOST_TEST_KEYCLOAK_URL", "http://127.0.0.1:8888")
KC_ADMIN_PW = os.environ.get("CIPHERPOST_TEST_KEYCLOAK_ADMIN_PASSWORD", "")
REALM = "cipherpost-test"
CLIENT = "cipherpost"
REDIRECT = "http://127.0.0.1:8899/callback"
USERS = {"alice": "AliceLab123!", "bob": "BobLab123!"}
RULES = ('[{"claim":"groups","match":"*mail-admins*","role":"admin"},'
         '{"claim":"groups","match":"*mail-analysts*","role":"analyst"}]')


def _admin_token():
    if not KC_ADMIN_PW:
        pytest.skip("CIPHERPOST_TEST_KEYCLOAK_ADMIN_PASSWORD not set")
    try:
        data = urllib.parse.urlencode({
            "grant_type": "password", "client_id": "admin-cli",
            "username": "admin", "password": KC_ADMIN_PW}).encode()
        req = urllib.request.Request(
            KC_URL + "/realms/master/protocol/openid-connect/token",
            data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)["access_token"]
    except Exception as e:
        pytest.skip(f"keycloak unreachable at {KC_URL}: {e}")


def _api(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(KC_URL + path, data=data, method=method,
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)


def _login_flow(username, password):
    """Full code+PKCE login via OUR builder; returns (claims, tokens)."""
    import re
    import httpx
    from app.core import oidc as O
    url, _ = O.new_authorize_url(REDIRECT)

    def jar():
        return "; ".join(f"{k}={v}" for k, v in c.cookies.items())

    def abs_url(loc):
        return loc if loc.startswith("http") else KC_URL + loc

    c = httpx.Client(follow_redirects=False, timeout=15)
    r = c.get(url)
    for _ in range(8):
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("location", "")
            if "code=" in loc and REDIRECT in loc:
                break
            assert loc, "empty redirect"
            r = c.get(abs_url(loc), headers={"Cookie": jar()})
            continue
        assert r.status_code == 200, f"unexpected {r.status_code}"
        m = re.search(r'action="([^"]+)"', r.text)
        assert m, "no form"
        action = abs_url(m.group(1).replace("&amp;", "&"))
        want = set(re.findall(r'name="([a-zA-Z]+)"', r.text))
        if "password" in want:
            fields = {"username": username, "password": password}
        else:
            fields = {"email": f"{username}@lab.test",
                      "firstName": username.title(), "lastName": "Lab"}
        r = c.post(action, data=fields, headers={"Cookie": jar()})
    else:
        raise AssertionError("login chain too deep")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    assert "code" in q, f"no code for {username}"
    stored = O.consume_state(q["state"])
    toks = O.exchange_code(q["code"], stored["verifier"], REDIRECT)
    claims = O.verify_id_token(toks["id_token"], stored.get("nonce"))
    return claims, toks, stored


@pytest.fixture()
def oidc_settings(monkeypatch):
    from app.core import config as _cfg
    from app.core import oidc as O
    monkeypatch.setattr(_cfg.settings, "OIDC_ISSUER", f"{KC_URL}/realms/{REALM}")
    monkeypatch.setattr(_cfg.settings, "OIDC_CLIENT_ID", CLIENT)
    monkeypatch.setattr(_cfg.settings, "OIDC_CLAIM_RULES", RULES)
    saved = dict(O._jwks_cache)
    O._jwks_cache.clear()
    try:
        yield _cfg.settings
    finally:
        O._jwks_cache.clear()
        O._jwks_cache.update(saved)


def test_keycloak_full_login_and_group_mapping(oidc_settings):
    _admin_token()  # skip unless IdP up
    from app.core import oidc as O
    claims, _, _ = _login_flow("alice", USERS["alice"])
    assert claims["email"] == "alice@lab.test"
    assert "mail-admins" in (claims.get("groups") or [])
    assert O.map_role_org(claims)[0] == "admin"
    claims, _, _ = _login_flow("bob", USERS["bob"])
    assert "mail-analysts" in (claims.get("groups") or [])
    assert O.map_role_org(claims)[0] == "analyst"


def test_keycloak_state_single_use_and_replay_rejected(oidc_settings):
    _admin_token()
    import httpx
    import re
    from app.core import oidc as O
    url, _ = O.new_authorize_url(REDIRECT)
    c = httpx.Client(follow_redirects=False, timeout=15)
    r = c.get(url)
    m = re.search(r'action="([^"]+)"', r.text)
    action = m.group(1).replace("&amp;", "&")
    jar = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
    r = c.post(action if action.startswith("http") else KC_URL + action,
               data={"username": "alice", "password": USERS["alice"]},
               headers={"Cookie": jar})
    loc = r.headers.get("location", "")
    # complete profile step if needed, then extract state without consuming twice
    q = {}
    if "code=" not in loc:
        r2 = c.get(loc if loc.startswith("http") else KC_URL + loc,
                   headers={"Cookie": "; ".join(f"{k}={v}" for k, v in c.cookies.items())})
        m2 = re.search(r'action="([^"]+)"', r2.text or "")
        if m2:
            a2 = m2.group(1).replace("&amp;", "&")
            r3 = c.post(a2 if a2.startswith("http") else KC_URL + a2,
                        data={"email": "alice@lab.test", "firstName": "Alice",
                              "lastName": "Lab"},
                        headers={"Cookie": "; ".join(f"{k}={v}" for k, v in c.cookies.items())})
            loc = r3.headers.get("location", loc)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    assert "code" in q
    O.consume_state(q["state"])
    with pytest.raises(ValueError):
        O.consume_state(q["state"])  # replay rejected


def test_keycloak_unknown_kid_refresh_and_expiry(oidc_settings):
    admin = _admin_token()
    from app.core import oidc as O
    # force JWKS refetch path (unknown-kid refresh covered when kids rotate)
    O._jwks_cache.clear()
    claims, toks, stored = _login_flow("alice", USERS["alice"])
    assert claims["email"] == "alice@lab.test"
    # short lifetime -> genuine expiry rejection, restored afterwards
    cur = _api("GET", f"/admin/realms/{REALM}", token=admin)[1]
    prev = cur.get("accessTokenLifespan")
    try:
        cur["accessTokenLifespan"] = 30
        _api("PUT", f"/admin/realms/{REALM}", body=cur, token=admin)
        claims2, toks2, stored2 = _login_flow("bob", USERS["bob"])
        assert claims2["email"] == "bob@lab.test"
        time.sleep(40)
        with pytest.raises(ValueError):
            O.verify_id_token(toks2["id_token"], stored2.get("nonce"))
    finally:
        cur = _api("GET", f"/admin/realms/{REALM}", token=admin)[1]
        cur["accessTokenLifespan"] = prev
        _api("PUT", f"/admin/realms/{REALM}", body=cur, token=admin)


def test_keycloak_disabled_user_rejected_and_restored(oidc_settings):
    admin = _admin_token()
    users = _api("GET", f"/admin/realms/{REALM}/users?username=bob",
                 token=admin)[1]
    uid = users[0]["id"]
    body = _api("GET", f"/admin/realms/{REALM}/users/{uid}", token=admin)[1]
    try:
        body["enabled"] = False
        _api("PUT", f"/admin/realms/{REALM}/users/{uid}", body=body,
             token=admin)
        with pytest.raises(Exception):
            _login_flow("bob", USERS["bob"])
    finally:
        body["enabled"] = True
        _api("PUT", f"/admin/realms/{REALM}/users/{uid}", body=body,
             token=admin)
    # restored user logs in again
    claims, _, _ = _login_flow("bob", USERS["bob"])
    assert claims["email"] == "bob@lab.test"
