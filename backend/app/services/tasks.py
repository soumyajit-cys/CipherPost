"""
Celery tasks for CipherPost analysis pipeline.

process_analysis_job(job_id):
  1. Read PCAP from disk
  2. Run Stage 2-3 (reassembly + rules engine)
  3. Run Stage 4 (ML scoring + SHAP)
  4. Persist everything to DB
  5. Generate reports (JSON + HTML)
"""
from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "cipherpost",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=600,
    worker_prefetch_multiplier=1,
)


def _get_sync_session():
    """Create a synchronous DB session for Celery workers (not async)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_size=5)
    return sessionmaker(bind=engine)()


@celery_app.task(bind=True, name="process_analysis_job")
def process_analysis_job(self, job_id: str):
    Session = _get_sync_session()
    try:
        job = Session.get("analysis_jobs", job_id)
        if not job:
            return {"error": "job not found"}

        job.status = "processing"
        job.progress = 0.05
        job.message = "Starting PCAP analysis..."
        Session.commit()

        # Stage 2-3: Parse + Rules
        from app.parsing.analysis import analyze_pcap
        job.progress = 0.1
        job.message = "Running protocol detection and TLS analysis..."
        Session.commit()

        analyses = analyze_pcap(
            job.pcap_path,
            trust_store=settings.TRUSTED_CA_BUNDLE_PATH,
        )
        job.progress = 0.5
        job.message = f"Parsed {len(analyses)} sessions, running rules engine..."
        Session.commit()

        # Stage 4: ML Scoring
        from app.ml.ml_engine import SessionScorer
        job.progress = 0.6
        job.message = "Running ML risk scoring and anomaly detection..."
        Session.commit()

        scorer = SessionScorer(trust_store=settings.TRUSTED_CA_BUNDLE_PATH)
        # Train on existing analyses (in production, would load historical data)
        scorer.train(analyses)
        scores = scorer.score_batch(analyses)

        job.progress = 0.8
        job.message = "Persisting results..."
        Session.commit()

        # Persist sessions + findings + SHAP to DB
        for sa, sr in zip(analyses, scores):
            from app.models.entities import Session as SessionModel, Finding, ShaPRow, Severity
            import uuid as _uuid

            sess_id = _uuid.uuid4().hex[:64]
            sess = SessionModel(
                id=sess_id, job_id=job_id,
                protocol=sa.protocol, five_tuple=sa.five_tuple,
                src_ip="", dst_ip="", src_port=0, dst_port=0,
                is_starttls=sa.is_starttls,
                tls_version=sa.negotiated_version_name,
                negotiated_cipher=sa.cipher,
                cipher_strength=sa.cipher_strength,
                key_length=sa.cipher_meta.key_len if sa.cipher_meta else None,
                pfs_supported=sa.cipher_meta.pfs if sa.cipher_meta else None,
                cert_chain_valid=(sa.chain_result == "ok"),
                cert_age_days=(
                    min(c.days_remaining for c in sa.certs if c.days_remaining is not None)
                    if sa.certs else None
                ),
                is_anomaly=sr.anomaly.is_anomaly,
                risk_score=sr.risk.posture_score,
                overall_finding_count=len(sa.findings),
                max_severity=(
                    max(
                        (f.severity for f in sa.findings),
                        key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0),
                        default=None
                    ) if sa.findings else None
                ),
            )
            Session.add(sess)

            for f in sa.findings:
                Session.add(Finding(
                    session_id=sess_id,
                    rule_id=f.rule_id, rule_name=f.rule_name,
                    severity=Severity(f.severity), title=f.title,
                    description=f.description, reference=f.reference,
                    kind=f.kind, evidence=f.evidence or {},
                ))

            for c in sr.shap_contributions:
                Session.add(ShaPRow(
                    session_id=sess_id, feature=c.feature,
                    value=c.value, impact=c.impact,
                ))

        # Fleet summary
        from app.models.entities import SessionSummary
        avg_score = sum(s.risk.posture_score for s in scores) / max(1, len(scores))
        Session.add(SessionSummary(job_id=job_id, key="fleet_posture_score", value=avg_score))
        Session.add(SessionSummary(job_id=job_id, key="total_sessions", value=len(analyses)))
        anomaly_count = sum(1 for s in scores if s.anomaly.is_anomaly)
        Session.add(SessionSummary(job_id=job_id, key="anomaly_count", value=anomaly_count))

        job.progress = 0.9
        job.message = "Generating reports..."
        Session.commit()

        # Generate reports
        from app.reporting.generator import generate_json, generate_html
        reports_dir = settings.REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)

        json_report = generate_json(analyses, scores, job.filename)
        (reports_dir / f"{job_id}.json").write_text(json_report)

        html_report = generate_html(analyses, scores, job.filename)
        (reports_dir / f"{job_id}.html").write_text(html_report)

        # Try PDF
        from app.reporting.generator import generate_pdf
        pdf_path = reports_dir / f"{job_id}.pdf"
        generate_pdf(html_report, str(pdf_path))

        job.progress = 1.0
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        job.message = f"Analysis complete: {len(analyses)} sessions, {sum(len(s.findings) for s in analyses)} findings"
        Session.commit()

        return {
            "job_id": job_id,
            "sessions": len(analyses),
            "findings": sum(len(s.findings) for s in analyses),
            "fleet_score": round(avg_score, 1),
        }

    except Exception as exc:
        job = Session.get("analysis_jobs", job_id)
        if job:
            job.status = "failed"
            job.error = str(exc)
            job.message = f"Analysis failed: {exc}"
            Session.commit()
        return {"error": str(exc)}
    finally:
        Session.close()
