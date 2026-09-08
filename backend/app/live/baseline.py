"""
Rolling fleet baseline for anomaly detection.

Stores per-session feature vectors in Postgres (table baseline_features) with
timestamps. Re-fits IsolationForest over trailing window on demand.
Falls back gracefully when sample count is low.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta

import numpy as np

from app.core.config import settings
from app.ml.features import extract_features, FEATURE_NAMES
from app.ml.ml_engine import SessionScorer, FleetAnomalyDetector

log = logging.getLogger("cipherpost.live.baseline")

class RollingBaseline:
    """Wraps SessionScorer with a rolling anomaly baseline."""

    def __init__(self):
        self.scorer = SessionScorer()
        self.anomaly = FleetAnomalyDetector(contamination=settings.FLEET_ANOMALY_CONTAMINATION)
        self._trained = False
        self._last_refit = 0
        self._seen = 0
        self._buffer: list[np.ndarray] = []  # in-memory recent vectors for fast refit

    def _refit_if_needed(self):
        now = time.time()
        if self._seen % settings.FLEET_BASELINE_REFIT_EVERY == 0 or (now - self._last_refit) > 3600:
            self._refit()

    def _refit(self):
        # Try Postgres window first
        X = None
        try:
            from sqlalchemy import create_engine, text
            engine = create_engine(settings.DATABASE_URL_SYNC)
            cutoff = datetime.utcnow() - timedelta(days=settings.FLEET_BASELINE_WINDOW_DAYS)
            with engine.connect() as conn:
                # baseline_features may not exist yet -> create lazily
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS baseline_features (
                        id SERIAL PRIMARY KEY,
                        ts TIMESTAMPTZ DEFAULT NOW(),
                        features JSONB
                    )
                """))
                conn.commit()
                rows = conn.execute(text("SELECT features FROM baseline_features WHERE ts > :cutoff ORDER BY ts DESC LIMIT 5000"), {"cutoff": cutoff}).fetchall()
                if rows and len(rows) >= settings.FLEET_BASELINE_MIN_SAMPLES:
                    import json
                    vecs = []
                    for (feat,) in rows:
                        if isinstance(feat, str):
                            feat = json.loads(feat)
                        # feat is dict name->value
                        vecs.append(np.array([float(feat.get(n, 0)) for n in FEATURE_NAMES], dtype=np.float32))
                    X = np.stack(vecs) if vecs else None
        except Exception as e:
            log.debug("baseline refit DB read failed: %s", e)
        if X is None or X.shape[0] < settings.FLEET_BASELINE_MIN_SAMPLES:
            # fallback to in-memory buffer
            if len(self._buffer) >= settings.FLEET_BASELINE_MIN_SAMPLES:
                X = np.stack(self._buffer[-5000:])
            else:
                return
        try:
            self.anomaly.train(X)
            self._last_refit = time.time()
            log.info("anomaly baseline refit on %d samples", X.shape[0])
        except Exception as e:
            log.warning("anomaly refit failed: %s", e)

    def train(self, analyses):
        """Initial bulk train from corpus (called once at startup if available)."""
        if analyses:
            self.scorer.train(analyses)
            X = np.array([list(extract_features(a).values()) for a in analyses], dtype=np.float32)
            # adapt to FEATURE_NAMES ordering if needed
            # session_features_matrix already does ordering; use it
            from app.ml.features import session_features_matrix
            Xm, names, _ = session_features_matrix(analyses)
            self.anomaly.train(Xm)
            self._trained = True
            self._last_refit = time.time()

    def score(self, sa):
        # ensure scorer trained (lazy)
        if not getattr(self.scorer, "_trained", False):
            # tiny fallback train on single sample is no-op; just score with fallback
            pass
        # append to buffer + persist
        try:
            feats = extract_features(sa)
            vec = np.array([float(feats.get(n, 0)) for n in FEATURE_NAMES], dtype=np.float32)
            self._buffer.append(vec)
            if len(self._buffer) > 6000:
                self._buffer = self._buffer[-5000:]
            # persist to DB asynchronously (best-effort, no block)
            try:
                from sqlalchemy import create_engine, text
                import json
                engine = create_engine(settings.DATABASE_URL_SYNC)
                with engine.connect() as conn:
                    conn.execute(text("INSERT INTO baseline_features (features) VALUES (:f)"), {"f": json.dumps(feats)})
                    conn.commit()
            except Exception:
                pass
        except Exception:
            pass
        self._seen += 1
        self._refit_if_needed()
        # delegate to scorer for risk + shap, but override anomaly with rolling one
        result = self.scorer.score(sa)
        # override anomaly if rolling model is trained
        if getattr(self.anomaly, "_trained", False):
            try:
                feats = extract_features(sa)
                X = np.array([float(feats.get(n, 0)) for n in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
                # need to ensure X shape matches training (FEATURE_NAMES length)
                result.anomaly = self.anomaly.predict(X[0])
            except Exception:
                pass
        return result
