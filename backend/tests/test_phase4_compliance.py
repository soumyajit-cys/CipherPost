"""Phase 4 Task 6: versioned compliance mapping + evidence bundles."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_mapping_loads_versioned_data():
    from app.proactive.compliance import (
        compliance_for, summary_for_findings, mapping_version, FRAMEWORKS)
    assert mapping_version() == 1
    assert set(FRAMEWORKS) >= {"PCI-DSS-4.0", "ISO-27001-2022", "NIST-CSF-2.0",
                               "OWASP-TLS", "CERT-In"}
    # pre-existing behavior preserved through the data move
    tags = compliance_for("expired-certificate")
    assert {t["control"] for t in tags} >= {"4.2", "A.8.24", "PR.DS-02"}
    # phase 4 rules mapped
    assert compliance_for("downgrade-attack-detected")
    assert compliance_for("tls-version-downgrade-suspected")
    assert compliance_for("outdated-client-stack")
    # every tag carries provenance
    for tags in (compliance_for("expired-certificate"),
                 compliance_for("starttls-strip-attempt")):
        for t in tags:
            assert t["framework_title"] and t["url"]
    out = summary_for_findings([{"rule_id": "expired-certificate",
                                 "severity": "high"}])
    assert out["groups"] and out["groups"][0]["count"] == 1


def test_evidence_bundle_roundtrip_and_tamper(tmp_path):
    from app.reporting.evidence import build_bundle, verify_bundle
    report = {"filename": "synthetic.pcap", "sessions": [{"five_tuple": "a-b"}],
              "findings": [{"rule_id": "expired-certificate", "observed": True}],
              "limitations": ["TLS 1.3 certs not observable"]}
    bundle = build_bundle(report, suppressions=[], retention={"sessions_days": 90},
                          versions={"tool": "0.3.0", "rules": "static", "mapping": 1})
    assert bundle["manifest"]["record_count"] == len(bundle["records"])
    assert verify_bundle(bundle)["ok"] is True
    # tamper with a record -> detected
    bundle["records"][0]["body"]["filename"] = "evil.pcap"
    assert verify_bundle(bundle)["ok"] is False
    # unobservable items labeled as such in the bundle
    manifest_labels = bundle["manifest"].get("labels", {})
    assert manifest_labels.get("unobservable", 0) >= 0


def test_cli_evidence_bundle_verifies():
    import json
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, "-m", "app.cli", "evidence",
         "../tests/fixtures/smtp_tls12_starttls.pcap"],
        capture_output=True, text=True, cwd="backend",
        env={**__import__("os").environ, "PYTHONPATH": "backend"})
    assert proc.returncode == 0, proc.stderr
    bundle = json.loads(proc.stdout)
    assert bundle["manifest"]["record_count"] == len(bundle["records"])
    from app.reporting.evidence import verify_bundle
    assert verify_bundle(bundle)["ok"] is True


def test_compliance_summary_and_evidence_api():
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.core.database import Base
    import app.models.entities as E
    from datetime import datetime, timezone
    engine = create_async_engine("sqlite+aiosqlite://")
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with maker() as s:
            now = datetime.now(timezone.utc)
            s.add(E.Organization(id="org-a", name="a"))
            s.add(E.AnalysisJob(id="j1", filename="x.pcap", pcap_path="x",
                                status=E.JobStatus.COMPLETED, org_id="org-a",
                                created_at=now))
            s.add(E.Session(id="s1", job_id="j1", protocol="SMTP",
                            five_tuple="1.1.1.1:1-2.2.2.2:25", src_ip="a", dst_ip="b",
                            src_port=1, dst_port=25, org_id="org-a", created_at=now,
                            details={"not_observable": []}))
            s.add(E.Finding(session_id="s1", rule_id="expired-certificate",
                            rule_name="w", severity=E.Severity.HIGH, title="t",
                            description="d", reference="", created_at=now))
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_init())
    from app.api.main import app
    from app.core.database import get_db
    from app.core.auth import get_current_user, AuthContext
    from fastapi.testclient import TestClient

    async def _db():
        async with maker() as s:
            yield s

    async def _user():
        return AuthContext(user_id="u", email="a@x", org_id="org-a",
                           role="analyst", via="jwt")

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = _user
    try:
        client = TestClient(app, raise_server_exceptions=False)
        comp = client.get("/api/v1/compliance/summary")
        assert comp.status_code == 200, comp.text
        assert comp.json()["mapping_version"] == 1
        ev = client.get("/api/v1/jobs/j1/evidence")
        assert ev.status_code == 200, ev.text
        bundle = ev.json()
        assert bundle["manifest"]["record_count"] == len(bundle["records"])
        assert bundle["manifest"]["versions"]["mapping"] == 1
        from app.reporting.evidence import verify_bundle
        assert verify_bundle(bundle)["ok"] is True
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)
