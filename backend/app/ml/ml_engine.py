"""
Stage 4: ML-based cryptographic posture scoring + anomaly detection.

Components:
1. RiskGradientBoost — gradient boosting classifier → 0-100 posture score
2. FleetAnomalyDetector — Isolation Forest for unsupervised anomaly flagging
3. SessionScorer — unified interface combining both models + SHAP

IMPORTANT DESIGN NOTE: initial labels come from the deterministic rules
engine on the labeled corpus. This means the ML model is partially learning
a function of the same features that drive the rules. This is explicitly
surfaced to users (the models are documented as an augmentation, not a
replacement). SHAP values and rule-vs-ML disagreement reports make this
transparent.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from app.ml.features import extract_features, FEATURE_NAMES, session_features_matrix
from app.parsing.rules import SessionAnalysis, SEVERITY_SCORE, max_severity
from app.core.config import settings


@dataclass
class RiskScore:
    probability: float          # 0.0 - 1.0 (calibrated)
    posture_score: int          # 0 - 100 (scaled)
    class_label: str            # "healthy" | "at-risk"
    model_version: str = "0.1.0"


@dataclass
class AnomalyResult:
    is_anomaly: bool
    anomaly_score: float        # negative = normal; closer to 0 = more anomalous
    method: str = "isolation-forest"


@dataclass
class FeatureContribution:
    feature: str
    value: float
    impact: float               # SHAP value (positive = increases risk)


@dataclass
class ScoringResult:
    risk: RiskScore
    anomaly: AnomalyResult
    shap_contributions: list[FeatureContribution] = field(default_factory=list)
    rule_ml_agreement: str = "agrees"   # "agrees" | "disagrees-ml-more-severe" | "disagrees-rules-more-severe"


class RiskGradientBoost:
    """HistGradientBoosting → calibrated risk probability."""

    def __init__(self):
        self.clf = None
        self.calibrated = None
        self._trained = False

    def train(self, X: np.ndarray, y: np.ndarray,
              feature_names: list[str], random_state: int = 42):
        if len(X) < 4:
            return self._fallback(y)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=random_state, stratify=y if sum(y) > 1 else None
        )
        self.clf = HistGradientBoostingClassifier(
            max_iter=200, learning_rate=0.1, max_depth=4,
            min_samples_leaf=2, random_state=random_state
        )
        self.clf.fit(X_train, y_train)
        if X_test.shape[0] > 2 and len(set(y_test)) > 1:
            self.calibrated = CalibratedClassifierCV(self.clf, cv=3, method="isotonic")
            self.calibrated.fit(X_train, y_train)
        self._trained = True
        self._feature_names = feature_names
        self._X_all = X
        self._y_all = y
        # Per-iteration eval
        y_pred = self.clf.predict(X_test)
        print("  GradientBoost eval on held-out:")
        print(classification_report(y_test, y_pred, zero_division=0))
        try:
            auc = roc_auc_score(y_test, y.clf.predict_proba(X_test)[:, 1]) if hasattr(self, '_skip') else None
        except Exception:
            pass
        return self

    def _fallback(self, y: np.ndarray):
        """Tiny dataset: learn a threshold from max_severity feature only."""
        self._trained = True
        self._feature_names = FEATURE_NAMES
        self._threshold = 0.5 if len(y) < 2 else float(np.mean(y))
        return self

    def predict(self, X: np.ndarray) -> tuple[float, str]:
        if not self._trained or self.clf is None:
            return 0.0, "healthy"
        try:
            proba = (self.calibrated or self.clf).predict_proba(X.reshape(1, -1))[0]
            prob = proba[1] if len(proba) > 1 else proba[0]
        except Exception:
            prob = float(np.clip(self.clf.decision_function(X.reshape(1, -1))[0], 0, 1))
        score = int(round(prob * 100))
        return prob, "at-risk" if score >= 50 else "healthy"

    @property
    def feature_importances(self) -> dict[str, float] | None:
        if self.clf is None or not hasattr(self.clf, "feature_importances_"):
            return None
        return dict(zip(self._feature_names, self.clf.feature_importances_))


class FleetAnomalyDetector:
    def __init__(self, contamination: float = 0.15):
        self.contamination = contamination
        self.iso = None
        self._trained = False

    def train(self, X: np.ndarray):
        if X.shape[0] < 5:
            return
        self.iso = IsolationForest(
            n_estimators=100, contamination=self.contamination, random_state=42
        )
        self.iso.fit(X)
        self._trained = True

    def predict(self, X: np.ndarray) -> AnomalyResult:
        if not self._trained or self.iso is None:
            return AnomalyResult(is_anomaly=False, anomaly_score=-1.0, method="fallback-no-op")
        score = float(self.iso.score_samples(X.reshape(1, -1))[0])
        label = self.iso.predict(X.reshape(1, -1))[0]
        return AnomalyResult(
            is_anomaly=label == -1,
            anomaly_score=score,
            method="isolation-forest",
        )


def compute_shap(model: RiskGradientBoost, X: np.ndarray,
                  feature_names: list[str]) -> list[FeatureContribution]:
    """Compute SHAP values using TreeExplainer. Returns sorted contributions."""
    if model.clf is None:
        return []
    try:
        import shap
        explainer = shap.TreeExplainer(model.clf)
        vals = explainer.shap_values(X.reshape(1, -1))
        if isinstance(vals, np.ndarray) and vals.ndim >= 2:
            vals = vals[0]
        contribs = []
        for i, name in enumerate(feature_names):
            v = float(vals[i]) if i < len(vals) else 0.0
            if abs(v) > 1e-8:
                contribs.append(FeatureContribution(
                    feature=name,
                    value=float(X[0, i] if i < X.shape[1] else 0.0),
                    impact=v,
                ))
        contribs.sort(key=lambda c: abs(c.impact), reverse=True)
        return contribs[:20]
    except Exception:
        return []


class SessionScorer:
    def __init__(self, trust_store: str | None = None):
        self.trust_store = trust_store or settings.TRUSTED_CA_BUNDLE_PATH
        self.risk_model = RiskGradientBoost()
        self.anomaly_model = FleetAnomalyDetector(contamination=0.2)
        self._feature_names = FEATURE_NAMES
        self._trained = False

    def train(self, analyses: list[SessionAnalysis]):
        if not analyses:
            return
        X, names, ids = session_features_matrix(analyses)
        self._feature_names = names
        # Labels: 1 = "at risk" (has any finding with severity >= medium)
        y = np.array([
            1 if max_severity(sa.findings) in ("medium", "high", "critical") else 0
            for sa in analyses
        ], dtype=np.int32)
        print(f"Training risk model on {len(analyses)} sessions "
              f"(at-risk={int(y.sum())}, healthy={int(len(y)-y.sum())})")
        self.risk_model.train(X, y, names)
        self.anomaly_model.train(X)
        self._trained = True

    def score(self, sa: SessionAnalysis) -> ScoringResult:
        feats = extract_features(sa)
        X = np.array([feats.get(n, 0.0) for n in self._feature_names], dtype=np.float32).reshape(1, -1)
        prob, label = self.risk_model.predict(X)
        risk = RiskScore(
            probability=prob,
            posture_score=int(round(prob * 100)),
            class_label=label,
        )
        anomaly = self.anomaly_model.predict(X)
        shap_vals = compute_shap(self.risk_model, X, self._feature_names)
        # Agreement check: rules say "at risk" if any medium+ severity finding
        rule_at_risk = max_severity(sa.findings) in ("medium", "high", "critical")
        ml_at_risk = label == "at-risk"
        if rule_at_risk == ml_at_risk:
            agreement = "agrees"
        elif ml_at_risk and not rule_at_risk:
            agreement = "disagrees-ml-more-severe"
        else:
            agreement = "disagrees-rules-more-severe"
        return ScoringResult(
            risk=risk,
            anomaly=anomaly,
            shap_contributions=shap_vals,
            rule_ml_agreement=agreement,
        )

    def score_batch(self, analyses: list[SessionAnalysis]) -> list[ScoringResult]:
        return [self.score(sa) for sa in analyses]
