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

def compute_drift(reference: np.ndarray, recent: np.ndarray,
                  feature_names: list[str], z_threshold: float = 3.0) -> dict:
    """Compare recent-window feature means vs a reference window.

    Returns per-feature standardized shifts plus an overall verdict. A drift
    verdict means *either* a real network change (new mail cluster, TLS
    policy rollout) *or* a data-quality problem (parser regression, clock
    skew) — both worth operator attention, hence an ops-level signal, not a
    user-facing finding. Pure function over arrays: unit-testable.
    """
    import math
    out = {"features": [], "drifted": [], "verdict": "ok"}
    if reference.shape[0] < 5 or recent.shape[0] < 5:
        out["verdict"] = "insufficient-data"
        return out
    ref_mean = reference.mean(axis=0)
    pooled_std = np.sqrt((reference.var(axis=0) + recent.var(axis=0)) / 2.0)
    rec_mean = recent.mean(axis=0)
    for i, name in enumerate(feature_names):
        std = float(pooled_std[i]) if i < len(pooled_std) else 0.0
        shift = float(rec_mean[i] - ref_mean[i]) if i < len(rec_mean) else 0.0
        z = shift / std if std > 1e-9 else 0.0
        flagged = abs(z) >= z_threshold and abs(shift) > 1e-9
        out["features"].append({"feature": name, "ref_mean": float(ref_mean[i]),
                                "recent_mean": float(rec_mean[i]),
                                "z": round(z, 3), "drifted": bool(flagged)})
        if flagged:
            out["drifted"].append(name)
    # verdict needs several features to move (single-feature moves are usually
    # policy rollouts, e.g. one cipher disabled fleet-wide)
    min_features = int(getattr(settings, "DRIFT_MIN_FEATURES", 3))
    out["verdict"] = "drift" if len(out["drifted"]) >= min_features else "ok"
    return out


def drift_from_db(hours_recent: int = 24, days_reference: int = 6) -> dict:
    """Load windows from baseline_features and run compute_drift."""
    from sqlalchemy import create_engine, text
    from datetime import timedelta
    try:
        engine = create_engine(settings.DATABASE_URL_SYNC)
        now = datetime.utcnow()
        with engine.connect() as conn:
            try:
                conn.execute(text("SELECT 1 FROM baseline_features LIMIT 1")).fetchall()
            except Exception:
                return {"verdict": "no-data", "features": [], "drifted": []}
            import json as _json

            def load(since, until=None):
                q = "SELECT features FROM baseline_features WHERE ts >= :since"
                params = {"since": since}
                if until is not None:
                    q += " AND ts < :until"
                    params["until"] = until
                q += " ORDER BY ts DESC LIMIT 5000"
                rows = conn.execute(text(q), params).fetchall()
                vecs = []
                for (feat,) in rows:
                    if isinstance(feat, str):
                        feat = _json.loads(feat)
                    vecs.append([float((feat or {}).get(n, 0)) for n in FEATURE_NAMES])
                return np.array(vecs, dtype=np.float32) if vecs else np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32)

            recent = load(now - timedelta(hours=hours_recent))
            reference = load(now - timedelta(days=days_reference),
                             now - timedelta(hours=hours_recent))
            return compute_drift(reference, recent, FEATURE_NAMES,
                                 float(getattr(settings, "DRIFT_Z_THRESHOLD", 3.0)))
    except Exception as e:
        log.debug("drift check skipped: %s", e)
        return {"verdict": "error", "features": [], "drifted": [], "error": str(e)[:200]}

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
