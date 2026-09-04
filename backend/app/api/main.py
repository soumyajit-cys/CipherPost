"""
FastAPI application — CipherPost API.

Endpoints:
  POST   /api/v1/upload          Upload PCAP → create analysis job
  GET    /api/v1/jobs             List all jobs
  GET    /api/v1/jobs/{id}       Job status + progress
  GET    /api/v1/jobs/{id}/sessions  Sessions for a job
  GET    /api/v1/jobs/{id}/findings  Findings for a job (severity-sorted)
  GET    /api/v1/jobs/{id}/report.{fmt}  Report: json, html, pdf
  GET    /api/v1/health           Health check
  GET    /metrics                 Prometheus metrics (if available)
"""
from __future__ import annotations

import os
import uuid
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.database import get_db, init_db
from app.models.entities import (
    AnalysisJob, Session, Finding, ShaPRow, SessionSummary, JobStatus, Severity,
)

app = FastAPI(
    title="CipherPost",
    version=settings.APP_VERSION,
    description="AI-assisted passive network forensic analysis of email infrastructure cryptography",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await init_db()


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


@app.post("/api/v1/upload", response_model=dict)
async def upload_pcap(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".pcap"):
        raise HTTPException(400, "Only .pcap files are accepted")
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")

    job_id = uuid.uuid4().hex[:64]
    pcap_path = settings.UPLOAD_DIR / f"{job_id}.pcap"
    with open(pcap_path, "wb") as f:
        f.write(content)

    job = AnalysisJob(
        id=job_id,
        filename=file.filename,
        pcap_path=str(pcap_path),
        status=JobStatus.PENDING,
        file_size=len(content),
    )
    db.add(job)
    await db.commit()

    # Dispatch Celery task
    from app.services.tasks import process_analysis_job
    process_analysis_job.delay(job_id)

    return {"job_id": job_id, "status": "pending", "filename": file.filename}


@app.get("/api/v1/jobs")
async def list_jobs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    q = select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": j.id, "filename": j.filename, "status": j.status.value,
            "progress": j.progress, "file_size": j.file_size,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        }
        for j in rows
    ]


@app.get("/api/v1/jobs/{job_id}")
async def get_job(job_id: str, db: AsyncSession = Depends(get_db)):
    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "id": job.id, "filename": job.filename, "status": job.status.value,
        "progress": job.progress, "message": job.message, "error": job.error,
        "file_size": job.file_size,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@app.get("/api/v1/jobs/{job_id}/sessions")
async def get_sessions(job_id: str, db: AsyncSession = Depends(get_db)):
    q = select(Session).where(Session.job_id == job_id).order_by(Session.risk_score.desc().nullslast())
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": s.id, "protocol": s.protocol, "five_tuple": s.five_tuple,
            "tls_version": s.tls_version, "negotiated_cipher": s.negotiated_cipher,
            "cipher_strength": s.cipher_strength, "pfs_supported": s.pfs_supported,
            "cert_chain_valid": s.cert_chain_valid, "cert_age_days": s.cert_age_days,
            "is_starttls": s.is_starttls, "is_anomaly": s.is_anomaly,
            "risk_score": s.risk_score, "max_severity": s.max_severity,
            "overall_finding_count": s.overall_finding_count,
            "details": s.details,
        }
        for s in rows
    ]


@app.get("/api/v1/jobs/{job_id}/findings")
async def get_findings(
    job_id: str,
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding).join(Session).where(Session.job_id == job_id)
    if severity:
        q = q.where(Finding.severity == Severity(severity))
    q = q.order_by(
        Finding.severity.desc(),
        Session.risk_score.desc().nullslast(),
    )
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": f.id, "session_id": f.session_id,
            "rule_id": f.rule_id, "rule_name": f.rule_name,
            "severity": f.severity.value, "title": f.title,
            "description": f.description, "reference": f.reference,
            "kind": f.kind, "evidence": f.evidence,
        }
        for f in rows
    ]


@app.get("/api/v1/jobs/{job_id}/shap")
async def get_shap(job_id: str, db: AsyncSession = Depends(get_db)):
    q = (
        select(ShaPRow)
        .join(Session)
        .where(Session.job_id == job_id)
        .order_by(func.abs(ShaPRow.impact).desc())
    )
    rows = (await db.execute(q)).scalars().all()
    return [
        {"session_id": r.session_id, "feature": r.feature,
         "value": r.value, "impact": r.impact, "method": r.method}
        for r in rows
    ]


@app.get("/api/v1/jobs/{job_id}/fleet")
async def get_fleet_summary(job_id: str, db: AsyncSession = Depends(get_db)):
    sessions_q = select(Session).where(Session.job_id == job_id)
    sessions = (await db.execute(sessions_q)).scalars().all()
    if not sessions:
        return {"total_sessions": 0, "fleet_score": 0, "severity_distribution": {}}
    total = len(sessions)
    avg_score = sum(s.risk_score or 0 for s in sessions) / total
    sev_dist = {}
    for s in sessions:
        sev_dist[s.max_severity or "none"] = sev_dist.get(s.max_severity or "none", 0) + 1
    return {
        "total_sessions": total,
        "fleet_score": round(avg_score, 1),
        "anomaly_count": sum(1 for s in sessions if s.is_anomaly),
        "severity_distribution": sev_dist,
        "sessions": [
            {"five_tuple": s.five_tuple, "protocol": s.protocol,
             "risk_score": s.risk_score, "is_anomaly": s.is_anomaly,
             "max_severity": s.max_severity, "tls_version": s.tls_version}
            for s in sessions
        ],
    }


@app.get("/api/v1/jobs/{job_id}/report.{fmt}")
async def get_report(job_id: str, fmt: str, db: AsyncSession = Depends(get_db)):
    if fmt not in ("json", "html", "pdf"):
        raise HTTPException(400, "Format must be json, html, or pdf")
    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != JobStatus.COMPLETED:
        raise HTTPException(409, "Job not yet completed")

    report_path = settings.REPORTS_DIR / f"{job_id}.{fmt}"
    if report_path.exists():
        if fmt == "html":
            return HTMLResponse(report_path.read_text())
        elif fmt == "json":
            return JSONResponse(report_path.read_text(), media_type="application/json")
        else:
            return Response(
                report_path.read_bytes(),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=cipherpost-{job_id}.pdf"},
            )

    # Generate on-the-fly if missing
    analyses, scores = await _load_analysis_from_db(job_id, db)
    from app.reporting.generator import generate_json, generate_html, generate_pdf
    if fmt == "json":
        content = generate_json(analyses, scores, job.filename)
        report_path.write_text(content)
        return JSONResponse(content)
    elif fmt == "html":
        content = generate_html(analyses, scores, job.filename)
        report_path.write_text(content)
        return HTMLResponse(content)
    else:
        html = generate_html(analyses, scores, job.filename)
        pdf_path = generate_pdf(html, str(report_path))
        if pdf_path and Path(pdf_path).exists():
            return Response(Path(pdf_path).read_bytes(), media_type="application/pdf")
        raise HTTPException(500, "PDF generation failed (WeasyPrint unavailable)")


async def _load_analysis_from_db(job_id: str, db):
    """Load SessionAnalysis objects from DB for report generation."""
    from app.parsing.rules import SessionAnalysis, Finding as RuleFinding
    from app.ml.ml_engine import ScoringResult, RiskScore, AnomalyResult

    sessions_q = select(Session).where(Session.job_id == job_id)
    sessions = (await db.execute(sessions_q)).scalars().all()
    analyses, scores = [], []
    for s in sessions:
        findings_q = select(Finding).where(Finding.session_id == s.id)
        findings = (await db.execute(findings_q)).scalars().all()
        sa = SessionAnalysis(
            session_id=s.id, protocol=s.protocol, five_tuple=s.five_tuple,
            is_starttls=s.is_starttls,
        )
        sa.tls_version = _version_hex(s.tls_version) if s.tls_version else None
        sa.cipher = s.negotiated_cipher
        sa.cipher_strength = s.cipher_strength
        sa.chain_result = "ok" if s.cert_chain_valid else "untrusted"
        sa.findings = [
            RuleFinding(
                rule_id=f.rule_id, rule_name=f.rule_name, severity=f.severity.value,
                title=f.title, description=f.description, reference=f.reference,
            )
            for f in findings
        ]
        analyses.append(sa)
        scores.append(ScoringResult(
            risk=RiskScore(probability=(s.risk_score or 0)/100, posture_score=s.risk_score or 0,
                           class_label="at-risk" if (s.risk_score or 0) >= 50 else "healthy"),
            anomaly=AnomalyResult(is_anomaly=s.is_anomaly, anomaly_score=-1.0),
        ))
    return analyses, scores


def _version_hex(ver_str: str | None) -> int | None:
    if not ver_str:
        return None
    mapping = {"SSLv3": 0x0300, "TLS 1.0": 0x0301, "TLS 1.1": 0x0302, "TLS 1.2": 0x0303, "TLS 1.3": 0x0304}
    return mapping.get(ver_str)
