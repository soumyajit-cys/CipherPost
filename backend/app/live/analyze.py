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

    def _persist(self, sa, scoring_result, raw_refs, session_raw_ts):
        """Persist session+findings+shap to Postgres using sync session."""
        Session = _get_sync_session()
        try:
            from app.models.entities import Session as SessionModel, Finding, ShaPRow, Severity
            sess_id = uuid.uuid4().hex
            # derive job: use LIVE_JOB_TAG as a synthetic job id (ensure exists)
            from app.models.entities import AnalysisJob, JobStatus
            job_id = settings.LIVE_JOB_TAG
            job = Session.get(AnalysisJob, job_id)
            if not job:
                job = AnalysisJob(id=job_id, filename="live-capture", pcap_path="live", status=JobStatus.PROCESSING, file_size=0)
                Session.add(job)
                Session.commit()
            # map fields
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
                overall_finding_count=len(sa.findings),
                max_severity= max((f.severity for f in sa.findings), key=lambda s: {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(s,0), default=None) if sa.findings else None,
                details={"raw_refs": raw_refs or [], "live_ts": session_raw_ts},
            )
            Session.add(sess)
            for f in sa.findings:
                Session.add(Finding(
                    session_id=sess_id, rule_id=f.rule_id, rule_name=f.rule_name,
                    severity=Severity(f.severity), title=f.title,
                    description=f.description, reference=f.reference,
                    kind=f.kind, evidence=f.evidence or {},
                ))
            if scoring_result:
                for c in scoring_result.shap_contributions:
                    Session.add(ShaPRow(session_id=sess_id, feature=c.feature, value=c.value, impact=c.impact))
            Session.commit()
            return sess_id
        except Exception as e:
            Session.rollback()
            log.warning("persist failed: %s", e)
            return None
        finally:
            Session.close()

    def _process_one(self, sess_payload: dict):
        try:
            sess = session_from_payload(sess_payload)
        except Exception as e:
            log.warning("session decode failed: %s", e)
            return
        raw_refs = getattr(sess, "raw_refs", None)
        # analyze
        try:
            sa = _analyze_session(sess, trust_store=settings.TRUSTED_CA_BUNDLE_PATH)
        except Exception as e:
            log.warning("analyze_session failed %s: %s", sess.five_tuple, e)
            return
        # score
        scoring = None
        try:
            # RollingBaseline has .score(sa) that also handles refit
            scoring = self.scorer.score(sa) if hasattr(self.scorer, "score") else None
        except Exception as e:
            log.debug("scoring failed: %s", e)
        # persist
        sess_id = self._persist(sa, scoring, raw_refs, sess.start_ts)
        # publish findings
        findings_payload = {
            "session_id": sess_id or sess.five_tuple,
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

    def run(self):
        log.info("analysis worker starting, stream=%s group=%s", settings.SESSION_STREAM, settings.ANALYSIS_CONSUMER_GROUP)
        self.gossip.start()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._signal)
            except ValueError:
                pass
        while not self._stop.is_set():
            items = self.consumer.poll(timeout_ms=800)
            if not items:
                continue
            for payload in items:
                if self._stop.is_set():
                    break
                try:
                    # payload is already decoded json dict from streams.StreamConsumer
                    # but our session payload is also json-encoded bytes; handle both
                    if isinstance(payload, dict) and "protocol" in payload:
                        sess_payload = payload
                    elif isinstance(payload, dict) and "v" in payload:
                        sess_payload = json.loads(payload["v"]) if isinstance(payload["v"], (bytes,str)) else payload["v"]
                    else:
                        sess_payload = payload
                    # if payload came via xreadgroup, it's the inner dict from session_to_payload
                    # which is itself json; ensure we pass dict
                    if isinstance(sess_payload, bytes):
                        sess_payload = json.loads(sess_payload)
                    self._process_one(sess_payload)
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
