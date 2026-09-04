"""
Stage 5-6 Integration tests: full pipeline from PCAP upload through analysis
to report generation. Tests run WITHOUT a database (uses SQLite in-memory)
and WITHOUT Redis/Celery (tests the task logic directly).
"""
import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest

FIXTURES = "tests/fixtures"


@pytest.fixture(scope="module")
def trust():
    path = f"{FIXTURES}/trusted_root.pem"
    return path if os.path.exists(path) else None


@pytest.fixture(scope="module")
def corpus_index(trust):
    path = f"{FIXTURES}/corpus_index.json"
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    with open(path) as f:
        return json.load(f)["files"]


# ── Full pipeline: PCAP → analysis → scoring → report ──────────────────────


def test_full_pipeline_all_sessions(trust, corpus_index):
    """Run the complete pipeline on every corpus PCAP and verify outputs."""
    from app.parsing.analysis import analyze_pcap
    from app.ml.ml_engine import SessionScorer
    from app.reporting.generator import generate_json, generate_html, build_report_data

    # Collect all analyses first (for training)
    all_analyses = []
    all_scores = []
    for ent in corpus_index:
        ap = analyze_pcap(f"{FIXTURES}/{ent['name']}.pcap", trust_store=trust)
        assert ap, f"{ent['name']} produced no sessions"
        all_analyses.extend(ap)

    # Train scorer on full corpus
    scorer = SessionScorer(trust_store=trust)
    scorer.train(all_analyses)

    # Score each session
    for sa in all_analyses:
        result = scorer.score(sa)
        all_scores.append(result)
        assert 0 <= result.risk.posture_score <= 100

    # Generate reports
    json_str = generate_json(all_analyses, all_scores, "test.pcap")
    data = json.loads(json_str)
    assert data["total_sessions"] == len(all_analyses)
    assert data["total_findings"] > 0
    assert "sessions" in data
    assert "findings" in data

    html_str = generate_html(all_analyses, all_scores, "test.pcap")
    assert "<html" in html_str
    assert "CipherPost" in html_str


def test_report_shap_included(trust, corpus_index):
    """Verify SHAP data is included in JSON report for scored sessions."""
    from app.parsing.analysis import analyze_pcap
    from app.ml.ml_engine import SessionScorer
    from app.reporting.generator import build_report_data

    analyses = []
    for ent in corpus_index:
        ap = analyze_pcap(f"{FIXTURES}/{ent['name']}.pcap", trust_store=trust)
        analyses.extend(ap)
    scorer = SessionScorer(trust_store=trust)
    scorer.train(analyses)
    scores = scorer.score_batch(analyses)
    data = build_report_data(analyses, scores, "test.pcap")
    # At least some sessions should have SHAP contributions
    has_shap = any(len(sd["contributions"]) > 0 for sd in data["shap_details"])
    assert has_shap, "No SHAP contributions in report"


def test_task_processing_direct(trust, corpus_index):
    """Simulate what Celery task does: run the full pipeline and persist to temp DB."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    from app.models.entities import AnalysisJob, Session, Finding, ShaPRow, SessionSummary, JobStatus
    from app.parsing.analysis import analyze_pcap
    from app.ml.ml_engine import SessionScorer
    from app.reporting.generator import generate_json, generate_html
    from datetime import datetime
    import uuid

    # In-memory SQLite
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    SyncSession = sessionmaker(bind=engine)

    # Create a job
    job_id = uuid.uuid4().hex[:64]
    with SyncSession() as db:
        job = AnalysisJob(id=job_id, filename="test.pcap", pcap_path="/dev/null", status=JobStatus.PENDING)
        db.add(job)
        db.commit()

        # Run analysis on one PCAP
        ent = corpus_index[0]
        analyses = analyze_pcap(f"{FIXTURES}/{ent['name']}.pcap", trust_store=trust)
        assert len(analyses) > 0

        scorer = SessionScorer(trust_store=trust)
        scorer.train(analyses)
        scores = scorer.score_batch(analyses)

        # Persist
        for sa, sr in zip(analyses, scores):
            sess_id = uuid.uuid4().hex[:64]
            sess = Session(
                id=sess_id, job_id=job_id,
                protocol=sa.protocol, five_tuple=sa.five_tuple,
                src_ip="", dst_ip="", src_port=0, dst_port=0,
                tls_version=sa.negotiated_version_name,
                negotiated_cipher=sa.cipher,
                risk_score=sr.risk.posture_score,
                is_anomaly=sr.anomaly.is_anomaly,
                cert_chain_valid=(sa.chain_result == "ok"),
                overall_finding_count=len(sa.findings),
            )
            db.add(sess)
            for f in sa.findings:
                db.add(Finding(
                    session_id=sess_id, rule_id=f.rule_id, rule_name=f.rule_name,
                    severity=f.severity, title=f.title,
                    description=f.description, reference=f.reference,
                ))
            for c in sr.shap_contributions:
                db.add(ShaPRow(session_id=sess_id, feature=c.feature, value=c.value, impact=c.impact))

        db.add(SessionSummary(job_id=job_id, key="fleet_score", value=sum(s.risk.posture_score for s in scores)/max(1,len(scores))))
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.utcnow()
        job.progress = 1.0
        db.commit()

        # Verify persisted data
        sessions = db.query(Session).filter(Session.job_id == job_id).all()
        assert len(sessions) == len(analyses)
        findings = db.query(Finding).join(Session).filter(Session.job_id == job_id).all()
        assert len(findings) > 0
        shaps = db.query(ShaPRow).join(Session).filter(Session.job_id == job_id).all()
        assert len(shaps) > 0

        # Generate reports from persisted data
        json_report = generate_json(analyses, scores, "test.pcap")
        assert json.loads(json_report)["total_sessions"] == len(analyses)

        html_report = generate_html(analyses, scores, "test.pcap")
        assert "CipherPost" in html_report


def test_findings_severity_sorted(trust, corpus_index):
    """Verify report findings are sorted by severity (critical first)."""
    from app.parsing.analysis import analyze_pcap
    from app.reporting.generator import build_report_data

    all_analyses = []
    for ent in corpus_index:
        ap = analyze_pcap(f"{FIXTURES}/{ent['name']}.pcap", trust_store=trust)
        all_analyses.extend(ap)

    data = build_report_data(all_analyses, filename="test.pcap")
    findings = data["findings"]
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for i in range(len(findings) - 1):
        a = sev_order.get(findings[i]["severity"], 0)
        b = sev_order.get(findings[i + 1]["severity"], 0)
        assert a >= b, f"Findings not sorted: {findings[i]['severity']} before {findings[i+1]['severity']}"


def test_fleet_summary_metrics(trust, corpus_index):
    """Verify fleet summary has expected aggregate metrics."""
    from app.parsing.analysis import analyze_pcap
    from app.ml.ml_engine import SessionScorer
    from app.reporting.generator import build_report_data

    analyses = []
    for ent in corpus_index:
        ap = analyze_pcap(f"{FIXTURES}/{ent['name']}.pcap", trust_store=trust)
        analyses.extend(ap)
    scorer = SessionScorer(trust_store=trust)
    scorer.train(analyses)
    scores = scorer.score_batch(analyses)
    data = build_report_data(analyses, scores, "test.pcap")

    assert data["fleet_posture_score"] >= 0
    assert data["fleet_posture_score"] <= 100
    assert data["total_sessions"] == len(analyses)
    assert data["total_findings"] > 0
    assert len(data["sessions"]) == len(analyses)
