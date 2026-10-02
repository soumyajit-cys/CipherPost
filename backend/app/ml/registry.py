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
from datetime import datetime, timezone
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
    entry = {"version": version, "trained_at": datetime.now(timezone.utc).isoformat(),
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


# --------------------------------------------------------------------------
# Phase 4: per-org models, candidates, promotion gating (never silent mixing)
# --------------------------------------------------------------------------

def _load_doc() -> dict:
    try:
        path = _registry_path()
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return {}


def _save_doc(doc: dict) -> None:
    try:
        _registry_path().write_text(json.dumps(doc, indent=2))
    except Exception as e:
        log.debug("registry write skipped: %s", e)


def code_version() -> str:
    try:
        import subprocess
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        sha = out.stdout.strip()
        if sha:
            return sha
    except Exception:
        pass
    return "unknown"


def dataset_hash(entries: list[dict]) -> str:
    canonical = sorted((e.get("session_id", ""), e.get("y"), e.get("source", ""))
                       for e in entries)
    return hashlib.sha256(repr(canonical).encode()).hexdigest()[:16]


def record_candidate(org_id: str, version: str, entry: dict) -> None:
    doc = _load_doc()
    orgs = doc.setdefault("orgs", {})
    slot = orgs.setdefault(org_id or "global", {"current": None, "history": []})
    entry = dict(entry, version=version, org_id=org_id or "global",
                 status="candidate")
    slot["history"].append(entry)
    slot["history"] = slot["history"][-20:]
    _save_doc(doc)


def org_current(org_id: str | None) -> dict | None:
    doc = _load_doc()
    slot = (doc.get("orgs", {}) or {}).get(org_id or "global", {})
    return slot.get("current")


def org_history(org_id: str | None, limit: int = 10) -> list[dict]:
    doc = _load_doc()
    slot = (doc.get("orgs", {}) or {}).get(org_id or "global", {})
    return (slot.get("history", []) or [])[-limit:]


def promote_candidate(org_id: str, version: str, reason: str) -> dict | None:
    doc = _load_doc()
    slot = (doc.get("orgs", {}) or {}).get(org_id or "global", {})
    for e in slot.get("history", []):
        if e.get("version") == version and e.get("status") == "candidate":
            e["status"] = "active"
            e["promoted_reason"] = reason
            prev = slot.get("current")
            if prev and prev.get("version") != version:
                prev["status"] = "superseded"
            slot["current"] = e
            _save_doc(doc)
            return e
    return None


def rollback_org(org_id: str) -> dict | None:
    """One-click rollback: reactivate the newest non-active prior version."""
    doc = _load_doc()
    slot = (doc.get("orgs", {}) or {}).get(org_id or "global", {})
    cands = [e for e in slot.get("history", [])
             if e.get("status") in ("active", "candidate", "superseded")]
    cur = (slot.get("current") or {}).get("version")
    priors = [e for e in reversed(cands) if e.get("version") != cur]
    if not priors:
        return None
    target = priors[0]
    target["status"] = "active"
    target["promoted_reason"] = "rollback"
    slot["current"] = target
    _save_doc(doc)
    return target
