"""
Model registry (track 5): every posture score / SHAP explanation references
the model version that produced it, so scores stay explainable and
reproducible as the model is retrained.

The registry is a small JSON file (`data/models/registry.json`, path from
MODELS_DIR). `record_training()` is called by SessionScorer.train(); the
current version is stamped onto every RiskScore. Versions are
`<base>-<n-samples>-<feature-hash8>` (e.g. `0.1.0-128-a3f9c2d1`): human
readable, content-linked, monotonic in training-set size.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path

from app.core.config import settings

log = logging.getLogger("cipherpost.ml.registry")

BASE_VERSION = "0.1.0"


def _registry_path() -> Path:
    d = Path(settings.MODELS_DIR)
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return d / "registry.json"


def _feature_hash(feature_names: list[str]) -> str:
    return hashlib.sha256(",".join(feature_names).encode()).hexdigest()[:8]


def record_training(n_samples: int, feature_names: list[str],
                    params: dict | None = None, metrics: dict | None = None) -> str:
    """Persist a training record; return the new model version."""
    version = f"{BASE_VERSION}-{n_samples}-{_feature_hash(list(feature_names))}"
    entry = {"version": version, "trained_at": datetime.utcnow().isoformat(),
             "n_samples": n_samples, "feature_names": list(feature_names),
             "params": params or {}, "metrics": metrics or {}}
    try:
        path = _registry_path()
        history = []
        if path.exists():
            try:
                history = json.loads(path.read_text()).get("history", [])
            except Exception:
                history = []
        history.append(entry)
        path.write_text(json.dumps({"current": entry, "history": history[-20:]}, indent=2))
    except Exception as e:
        log.debug("registry write skipped: %s", e)
    return version


def current_version() -> str:
    """Latest recorded version, or the base version if never trained."""
    try:
        path = _registry_path()
        if path.exists():
            return json.loads(path.read_text())["current"]["version"]
    except Exception:
        pass
    return BASE_VERSION


def history(limit: int = 10) -> list[dict]:
    try:
        path = _registry_path()
        if path.exists():
            return json.loads(path.read_text()).get("history", [])[-limit:]
    except Exception:
        pass
    return []
