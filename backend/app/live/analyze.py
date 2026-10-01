"""
Analysis worker: consumes Sessions from Redis Stream, runs the shared
Stage-3 engine (analyze_session), scores via ML, persists to Postgres,
publishes findings onto findings stream + pubsub for SSE/dashboard.
"""
from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
import uuid
from datetime import datetime
from typing import Any

import redis

from app.core.config import settings
from app.live.serialize import session_from_payload
from app.live import streams as bus
from app.live.metrics import Gossiper

log = logging.getLogger("cipherpost.live.analyze")

# Lazy imports to avoid heavy deps at import time
def _analyze_session(sess, trust_store=None):
    from app.parsing.analysis import analyze_session
    return analyze_session(sess, trust_store=trust_store)

def _score_session(sa, scorer):
    return scorer.score(sa)

def _get_sync_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_size=5)
    return sessionmaker(bind=engine)()


def deterministic_session_id(payload: dict) -> str:
    """Stable id for (five_tuple, start_ts, end_ts, endpoints) so redelivery
    cannot create duplicates. Falls back to uuid4 only when keys are missing."""
    import hashlib
    try:
        key = "|".join([
            str(payload.get("five_tuple", "")),
            str(payload.get("start_ts", "")),
            str(payload.get("end_ts", "")),
            str(payload.get("client_ip", "")),
            str(payload.get("server_ip", "")),
            str(payload.get("client_port", "")),
            str(payload.get("server_port", "")),
        ])
        if key.strip("|"):
            return "sess-" + hashlib.sha256(key.encode()).hexdigest()[:32]
    except Exception:
        pass
    return "sess-" + uuid.uuid4().hex[:32]

class AnalysisWorker:
    def __init__(self, redis_client=None, scorer=None):
        self.r = redis_client or redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
        self.gossip = Gossiper(self.r, "analysis", interval=5)
        self._stop = threading.Event()
        self.scorer = scorer  # SessionScorer or RollingBaseline wrapper
        self._init_scorer()
        self.consumer = bus.StreamConsumer(self.r, settings.SESSION_STREAM, settings.ANALYSIS_CONSUMER_GROUP, f"analyzer-{uuid.uuid4().hex[:6]}")

    def _init_scorer(self):
        if self.scorer is not None:
            return
        try:
            from app.live.baseline import RollingBaseline
            self.scorer = RollingBaseline()
            log.info("analysis scorer: RollingBaseline (window=%dd)", settings.FLEET_BASELINE_WINDOW_DAYS)
        except Exception as e:
            log.warning("RollingBaseline init failed, fallback to SessionScorer: %s", e)
            from app.ml.ml_engine import SessionScorer
            self.scorer = SessionScorer()

    def _signal(self, signum, frame):
        log.info("signal %s", signum)
        self._stop.set()

    def _default_org_id(self, Session) -> str | None:
        """Cached lookup of the default org id (live sensor scope)."""
        if getattr(self, "_org_cache", None) is not None:
            return self._org_cache
        try:
            from app.models.entities import Organization
            org = Session.query(Organization).filter(
                Organization.name == settings.DEFAULT_ORG_NAME).first()
            self._org_cache = org.id if org else None
        except Exception:
            self._org_cache = None
        return self._org_cache

    def _persist(self, sa, scoring_result, raw_refs, session_raw_ts,
                 session_id: str | None = None,
                 payload_org_id: str | None = None):
        """Persist session+findings+shap to Postgres using sync session.

        Idempotent: if `session_id` already exists, returns (id, False, org)
        without inserting duplicates. Org resolution (fail closed): the
        ingest-stamped org wins; otherwise the default org only in explicit
        single-tenant mode; otherwise raise (dead-letter, never mis-attribute).
        """
        Session = _get_sync_session()
        try:
            from app.models.entities import Session as SessionModel, Finding, ShaPRow, Severity
            sess_id = session_id or uuid.uuid4().hex
            existing = Session.get(SessionModel, sess_id)
            if existing is not None:
                return sess_id, False, existing.org_id
            if payload_org_id:
                org_id = payload_org_id
            elif settings.SINGLE_TENANT:
                org_id = self._default_org_id(Session)
            else:
                raise ValueError(
                    "unstamped session in multi-tenant mode "
                    "(sensors must use agent tokens via /api/v1/ingest/sessions)")
            # derive job: per-org synthetic job rows (legacy "live" for default)
            from app.models.entities import AnalysisJob, JobStatus
            default_org_id = self._default_org_id(Session)
            job_id = (settings.LIVE_JOB_TAG if org_id == default_org_id
                      else f"{settings.LIVE_JOB_TAG}-{org_id}")
            job = Session.get(AnalysisJob, job_id)
            if not job:
                job = AnalysisJob(id=job_id, filename="live-capture", pcap_path="live", status=JobStatus.PROCESSING, file_size=0, org_id=org_id)
                Session.add(job)
                Session.commit()
            elif job.org_id is None and org_id:
                job.org_id = org_id
            # flow aggregation + regression: compare against best-seen state,
            # then append any proven regression finding before persisting.
            try:
                from app.live.flows import update_flow
                _proto = sa.protocol.value if hasattr(sa.protocol, "value") else str(sa.protocol)
                _tls_name = getattr(sa, "negotiated_version_name", None)
                _encrypted = _tls_name is not None
                _flow, _regression = update_flow(
                    Session, org_id,
                    {"five_tuple": sa.five_tuple, "protocol": _proto},
                    _tls_name, getattr(sa, "cipher", None), _encrypted)
                if _regression:
                    from app.parsing.rules import Finding as _RuleFinding
                    sa.findings.append(_RuleFinding(
                        rule_id=_regression["rule_id"],
                        rule_name="transport-regression",
                        severity=_regression["severity"],
                        title=_regression["title"],
                        description=_regression["title"],
                        reference="RFC 8461 posture continuity",
                    ))
                    try:
                        self.gossip.counters.inc("flow_regressions")
                    except Exception:
                        pass
            except Exception as e:
                log.debug("flow aggregation skipped: %s", e)
            # map fields
            from datetime import datetime, timezone
            _now = datetime.now(timezone.utc)
            sess = SessionModel(
                id=sess_id, job_id=job_id,
                protocol=sa.protocol, five_tuple=sa.five_tuple,
                src_ip=getattr(sa, "client_ip", "") or "",
                dst_ip=getattr(sa, "server_ip", "") or "",
                src_port=0, dst_port=0,
                is_starttls=sa.is_starttls,
                tls_version=sa.negotiated_version_name,
                negotiated_cipher=sa.cipher,
                cipher_strength=sa.cipher_strength,
                key_length=sa.cipher_meta.key_len if getattr(sa, "cipher_meta", None) else None,
                pfs_supported=sa.cipher_meta.pfs if getattr(sa, "cipher_meta", None) else None,
                cert_chain_valid=(sa.chain_result == "ok"),
                cert_age_days= min((c.days_remaining for c in sa.certs if c.days_remaining is not None), default=None) if sa.certs else None,
                is_anomaly=scoring_result.anomaly.is_anomaly if scoring_result else False,
                risk_score=scoring_result.risk.posture_score if scoring_result else None,
                model_version=(scoring_result.risk.model_version if scoring_result else None),
                overall_finding_count=len(sa.findings),
                max_severity= max((f.severity for f in sa.findings), key=lambda s: {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(s,0), default=None) if sa.findings else None,
                org_id=default_org_id,
                details={"raw_refs": raw_refs or [], "live_ts": session_raw_ts},
                created_at=_now,
            )
            Session.add(sess)
            for f in sa.findings:
                Session.add(Finding(
                    session_id=sess_id, rule_id=f.rule_id, rule_name=f.rule_name,
                    severity=Severity(f.severity), title=f.title,
                    description=f.description, reference=f.reference,
                    kind=f.kind, evidence=f.evidence or {},
                    created_at=_now,
                ))
            if scoring_result:
                for c in scoring_result.shap_contributions:
                    Session.add(ShaPRow(session_id=sess_id, feature=c.feature, value=c.value, impact=c.impact))
            try:
                from app.proactive.certs import track_session_certs
                track_session_certs(sa, default_org_id, Session)
            except Exception:
                pass
            Session.commit()
            return sess_id, True
        except Exception as e:
            Session.rollback()
            log.warning("persist failed: %s", e)
            raise
        finally:
            Session.close()

    def _process_one(self, sess_payload: dict):
        """Process one session payload. Raises on failure (caller decides
        retry vs dead-letter). Returns (sess_id, created)."""
        try:
            sess = session_from_payload(sess_payload)
        except Exception as e:
            log.warning("session decode failed: %s", e)
            raise
        raw_refs = getattr(sess, "raw_refs", None)
        # analyze
        try:
            sa = _analyze_session(sess, trust_store=settings.TRUSTED_CA_BUNDLE_PATH)
        except Exception as e:
            log.warning("analyze_session failed %s: %s", sess.five_tuple, e)
            raise
        # score
        scoring = None
        try:
            # RollingBaseline has .score(sa) that also handles refit
            scoring = self.scorer.score(sa) if hasattr(self.scorer, "score") else None
        except Exception as e:
            log.debug("scoring failed: %s", e)
        # persist (idempotent on deterministic session id)
        sess_id, created = self._persist(
            sa, scoring, raw_refs, sess.start_ts,
            session_id=deterministic_session_id(sess_payload if isinstance(sess_payload, dict) else {}),
        )
        if not created:
            # Redelivery: already stored, ack without republishing findings.
            self.gossip.counters.inc("sessions_duplicate_skipped")
            return sess_id, False
        # publish findings
        findings_payload = {
            "session_id": sess_id or sess.five_tuple,
            "org_id": getattr(self, "_org_cache", None),
            "five_tuple": sess.five_tuple,
            "protocol": sess.protocol.value if hasattr(sess.protocol, "value") else str(sess.protocol),
            "findings": [{"rule_id": f.rule_id, "severity": f.severity, "title": f.title} for f in sa.findings],
            "risk_score": scoring.risk.posture_score if scoring else None,
            "is_anomaly": scoring.anomaly.is_anomaly if scoring else False,
            "max_severity": max((f.severity for f in sa.findings), default="none"),
            "ts": time.time(),
        }
        try:
            bus.publish_finding(self.r, findings_payload)
            bus.notify(self.r, "findings", "finding", findings_payload)
            bus.notify(self.r, "sessions", "session", findings_payload)
        except Exception as e:
            log.debug("publish findings failed: %s", e)
        self.gossip.counters.inc("sessions_analyzed")
        if scoring and scoring.anomaly.is_anomaly:
            self.gossip.counters.inc("anomalies")
        # queue depth gossip
        try:
            self.gossip.counters.set("queue_depth", self.consumer.queue_depth())
        except Exception:
            pass
        try:
            self.gossip.counters.set("dlq_depth", self.consumer.dlq_depth())
        except Exception:
            pass
        return sess_id, True

    def _handle_entry(self, entry_id: str, payload: Any) -> None:
        """Process one stream entry with retry accounting and DLQ.

        ACKs only after durable handling. Poison messages go to the dead-letter
        stream after STREAM_MAX_ATTEMPTS attempts.
        """
        if isinstance(payload, dict) and "protocol" in payload:
            sess_payload = payload
        elif isinstance(payload, dict) and "v" in payload:
            v = payload["v"]
            sess_payload = json.loads(v) if isinstance(v, (bytes, str)) else v
        else:
            sess_payload = payload
        if isinstance(sess_payload, bytes):
            sess_payload = json.loads(sess_payload)
        try:
            self._process_one(sess_payload)
        except Exception as e:
            attempts = bus.note_attempt(self.r, self.consumer.stream, entry_id)
            if attempts >= settings.STREAM_MAX_ATTEMPTS:
                self.consumer.dead_letter(entry_id, sess_payload
                                          if isinstance(sess_payload, dict) else {},
                                          str(e), attempts)
                try:
                    self.gossip.counters.inc("sessions_dead_lettered")
                except Exception:
                    pass
                log.warning("session %s dead-lettered after %d attempts: %s",
                            entry_id, attempts, e)
            else:
                log.debug("session %s attempt %d failed, will redeliver: %s",
                          entry_id, attempts, e)
            return
        bus.clear_attempts(self.r, self.consumer.stream, entry_id)
        self.consumer.ack(entry_id)

    def run(self):
        log.info("analysis worker starting, stream=%s group=%s", settings.SESSION_STREAM, settings.ANALYSIS_CONSUMER_GROUP)
        self.gossip.start()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._signal)
            except ValueError:
                pass
        while not self._stop.is_set():
            items = self.consumer.poll_raw(timeout_ms=800)
            if not items:
                # Reclaim entries stuck with dead consumers, then idle briefly.
                for eid, payload in self.consumer.reclaim():
                    if self._stop.is_set():
                        break
                    try:
                        self._handle_entry(eid, payload)
                    except Exception as e:
                        log.warning("reclaim process error: %s", e)
                continue
            for entry_id, payload in items:
                if self._stop.is_set():
                    break
                try:
                    self._handle_entry(entry_id, payload)
                except Exception as e:
                    log.warning("process error: %s", e)
        self.gossip.stop()
        log.info("analysis worker stopped")

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="CipherPost analysis worker")
    ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    w = AnalysisWorker()
    w.run()
    return 0

if __name__ == "__main__":
    sys.exit(main())
