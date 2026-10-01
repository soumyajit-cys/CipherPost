"""
Track 4: SIEM/ticketing adapters + SDK route-coverage contract test.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

ALERT = {"id": "a1", "ts": 1.0, "severity": "critical", "title": "RC4 cipher",
         "description": "rc4 negotiated", "rule_id": "rc4-cipher",
         "five_tuple": "1.1.1.1:1->2.2.2.2:25", "protocol": "SMTP",
         "risk_score": 90, "findings": []}


def test_splunk_adapter_posts_hec(monkeypatch):
    from app.live.alerts import SplunkHECAdapter
    calls = {}

    class FakeResp:
        status_code = 200

    def fake_post(url, json=None, headers=None, timeout=None, verify=None):
        calls["url"] = url
        calls["headers"] = headers
        calls["json"] = json
        return FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    ad = SplunkHECAdapter("https://splunk:8088/services/collector",
                          "tok", index="mail")
    assert ad.send(ALERT) is True
    assert calls["headers"] == {"Authorization": "Splunk tok"}
    assert calls["json"]["event"]["rule_id"] == "rc4-cipher"
    assert calls["json"]["index"] == "mail"
    assert calls["json"]["sourcetype"] == "cipherpost:alert"


def test_jira_backend_create(monkeypatch):
    from app.live.ticketing import JiraBackend, should_ticket
    calls = {}

    class FakeResp:
        status_code = 201

        def json(self):
            return {"key": "SEC-42"}

    def fake_post(url, json=None, auth=None, timeout=None):
        calls["url"] = url
        calls["auth"] = auth
        calls["json"] = json
        return FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    j = JiraBackend("https://x.atlassian.net", "a@b.c", "tok", "SEC")
    url = j.create(ALERT)
    assert url == "https://x.atlassian.net/browse/SEC-42"
    assert calls["auth"] == ("a@b.c", "tok")
    assert "RC4" in calls["json"]["fields"]["summary"]
    assert should_ticket(ALERT) is True
    assert should_ticket({**ALERT, "severity": "low"}) is False


def test_python_sdk_paths_match_server_routes():
    """Contract test: every SDK-covered path must exist in the FastAPI table."""
    import re
    import sys
    sys.path.insert(0, os.path.abspath("sdk/python"))
    from cipherpost_client import CipherPostClient
    from app.api.main import app

    src = open("sdk/python/cipherpost_client.py").read()
    sdk_paths = set(re.findall(r'"(/api/v1[^"]*)"', src))
    # strip path params for comparison
    route_templates = set()
    for r in app.routes:
        path = getattr(r, "path", "")
        if path.startswith("/api/v1"):
            route_templates.add(path)
    import re as _re

    def matches(sdk_path: str) -> bool:
        # convert {job_id} style + concrete ids to regex
        for t in route_templates:
            pattern = "^" + _re.escape(t).replace(r"\{job_id\}", "[^/]+").replace(r"\{fmt\}", "[^/]+").replace(r"\{domain\}", "[^/]+").replace(r"\{key_id\}", "[^/]+").replace(r"\{user_id\}", "[^/]+") + "$"
            # also handle f-string concrete interpolation already done in SDK
            t2 = _re.sub(r"\{[^}]+\}", "[^/]+", "^" + t + "$")
            if _re.match(t2, sdk_path):
                return True
        return False

    missing = sorted(p for p in sdk_paths if not matches(p))
    assert not missing, f"SDK paths missing from server: {missing}"


def _sdk_paths_from(source: str, pattern: str) -> set[str]:
    import re
    return set(re.findall(pattern, source))


def _openapi_paths() -> set[str]:
    import json
    with open("docs/openapi.json") as f:
        return set(json.load(f)["paths"].keys())


def test_both_sdks_match_committed_openapi_schema():
    """Contract: SDK paths and the committed docs/openapi.json agree with the
    live app (catches stale schema and SDK drift in one place)."""
    import re
    py_src = open("sdk/python/cipherpost_client.py").read()
    ts_src = open("sdk/typescript/cipherpost.ts").read()
    py_paths = _sdk_paths_from(py_src, r'"(/api/v1[^"]*)"')
    ts_paths = _sdk_paths_from(ts_src, r"'(/api/v1[^']*)'")
    schema_paths = _openapi_paths()

    def template(path: str) -> str:
        out = re.sub(r"\{[^}]+\}", "{x}", path)
        # f-string concrete ids used by the Python SDK
        out = re.sub(r"/(key-|user-|at-)[^/]*$", "/{x}", out)
        out = re.sub(r"/jobs/[^/]+/report\.[a-z]+$", "/jobs/{x}/report.{x}", out)
        return out

    schema_templates = {template(p) for p in schema_paths}
    for label, paths in (("python", py_paths), ("typescript", ts_paths)):
        missing = sorted(p for p in paths if template(p) not in schema_templates)
        assert not missing, f"{label} SDK paths missing from docs/openapi.json: {missing}"


def test_openapi_baseline_is_current():
    """docs/openapi.json must match the live app (regenerate if this fails)."""
    import json
    from app.api.main import app
    with open("docs/openapi.json") as f:
        baseline = json.load(f)
    live_paths = set(app.openapi()["paths"].keys())
    assert set(baseline["paths"].keys()) == live_paths, (
        "docs/openapi.json is stale; run scripts/export_openapi.py")
