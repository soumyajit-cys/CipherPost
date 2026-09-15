"""
CipherPost Python SDK (track 4) — typed client over /api/v1.

Zero third-party deps (stdlib urllib). Auth: login() stores a JWT, or pass
api_key="cp_..." for X-API-Key auth used by SIEM integrations/scripts.

Covers: auth, jobs, sessions, findings, shap, fleet, reports, alerts,
agents, certs, compliance, audit. Field names mirror the OpenAPI schema
(snake_case); run `pytest backend/tests/test_track4_sdk.py` to verify the
paths stay in sync with the server route table.
"""
from __future__ import annotations

import io
import json
import urllib.parse
import urllib.request


class CipherPostError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"cipherpost api error {status}: {body[:300]}")
        self.status = status
        self.body = body


class CipherPostClient:
    def __init__(self, base_url: str = "http://localhost:8000",
                 token: str | None = None, api_key: str | None = None,
                 timeout: float = 15):
        self.base = base_url.rstrip("/")
        self.token = token
        self.api_key = api_key
        self.timeout = timeout

    # -- low level ------------------------------------------------------
    def _headers(self, extra: dict | None = None) -> dict:
        h = dict(extra or {})
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def _req(self, method: str, path: str, body=None, raw: bool = False):
        data = None
        headers = self._headers()
        if body is not None and not isinstance(body, (bytes, io.IOBase)):
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        elif isinstance(body, io.IOBase):
            data = body.read()
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                payload = r.read()
                if raw:
                    return payload
                return json.loads(payload or b"{}")
        except urllib.error.HTTPError as e:
            raise CipherPostError(e.code, e.read().decode(errors="replace"))

    def _get(self, path: str, params: dict | None = None):
        if params:
            path += "?" + urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None})
        return self._req("GET", path)

    # -- auth ------------------------------------------------------------
    def login(self, email: str, password: str) -> dict:
        out = self._req("POST", "/api/v1/auth/login",
                        {"email": email, "password": password})
        self.token = out["token"]
        return out

    def me(self) -> dict:
        return self._get("/api/v1/auth/me")

    # -- jobs / analyses ---------------------------------------------------
    def list_jobs(self, limit: int = 50, offset: int = 0) -> list:
        return self._get("/api/v1/jobs", {"limit": limit, "offset": offset})

    def get_job(self, job_id: str) -> dict:
        return self._get(f"/api/v1/jobs/{job_id}")

    def job_sessions(self, job_id: str) -> list:
        return self._get(f"/api/v1/jobs/{job_id}/sessions")

    def job_findings(self, job_id: str, severity: str | None = None) -> list:
        return self._get(f"/api/v1/jobs/{job_id}/findings", {"severity": severity})

    def job_shap(self, job_id: str) -> list:
        return self._get(f"/api/v1/jobs/{job_id}/shap")

    def job_fleet(self, job_id: str) -> dict:
        return self._get(f"/api/v1/jobs/{job_id}/fleet")

    def report(self, job_id: str, fmt: str = "json") -> bytes:
        return self._req("GET", f"/api/v1/jobs/{job_id}/report.{fmt}", raw=True)

    def upload_pcap(self, path: str) -> dict:
        import uuid
        boundary = uuid.uuid4().hex
        with open(path, "rb") as f:
            content = f.read()
        name = path.split("/")[-1]
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() \
            + content + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(
            self.base + "/api/v1/upload", data=body, method="POST",
            headers={**self._headers(), "Content-Type": f"multipart/form-data; boundary={boundary}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise CipherPostError(e.code, e.read().decode(errors="replace"))

    # -- live / fleet ------------------------------------------------------
    def sessions(self, protocol: str | None = None, severity: str | None = None,
                 limit: int = 50) -> list:
        return self._get("/api/v1/sessions",
                         {"protocol": protocol, "severity": severity, "limit": limit})

    def findings(self, severity: str | None = None, protocol: str | None = None,
                 limit: int = 50) -> list:
        return self._get("/api/v1/findings",
                         {"severity": severity, "protocol": protocol, "limit": limit})

    def fleet_trend(self, days: int = 7) -> dict:
        return self._get("/api/v1/fleet/trend", {"days": days})

    def live_status(self) -> dict:
        return self._get("/api/v1/live/status")

    def agents(self) -> dict:
        return self._get("/api/v1/agents")

    # -- alerts / certs / compliance ---------------------------------------
    def alerts(self, limit: int = 50) -> list:
        return self._get("/api/v1/alerts", {"limit": limit})

    def certs(self, limit: int = 100) -> list:
        return self._get("/api/v1/certs", {"limit": limit})

    def certs_expiring(self, days: int = 30) -> list:
        return self._get("/api/v1/certs/expiring", {"days": days})

    def compliance_summary(self, framework: str | None = None) -> dict:
        return self._get("/api/v1/compliance/summary", {"framework": framework})

    def audit(self, limit: int = 100, action: str | None = None) -> list:
        return self._get("/api/v1/audit", {"limit": limit, "action": action})
