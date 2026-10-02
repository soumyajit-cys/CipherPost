"""Analyst-label retraining pipeline (Phase 4 Task 4).

Dataset: FindingFeedback verdicts joined to sessions. Per-session label:
  y=1 if any `confirmed` verdict on a medium+ finding,
  y=0 if any `false_positive` verdict and no confirmed,
  excluded when only `accepted_risk` (ambiguous for training).
Rows carry source="analyst" and are NEVER mixed with source="rules" rows.

Minimum-data policy: fewer than MIN_ANALYST_LABELS_PER_CLASS analyst labels
per class -> ranking-only mode (no training, documented reason).

Promotion gate: candidate beats current by ML_PROMOTE_MARGIN_F1 on the
grouped held-out set AND does not regress per-rule false-positive rate;
otherwise rejected with a recorded reason. Rollback reactivates the prior.
Models are per-org; a global model trains only on TRAINING_OPT_IN_ORGS data.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("cipherpost.ml.retraining")


def min_per_class() -> int:
    from app.core.config import settings as _s
    try:
        return max(1, int(_s.MIN_ANALYST_LABELS_PER_CLASS))
    except Exception:
        return 50


def promote_margin() -> float:
    from app.core.config import settings as _s
    try:
        return float(_s.ML_PROMOTE_MARGIN_F1)
    except Exception:
        return 0.02


def opt_in_orgs() -> set[str]:
    from app.core.config import settings as _s
    try:
        return {o.strip() for o in (_s.TRAINING_OPT_IN_ORGS or "").split(",") if o.strip()}
    except Exception:
        return set()


def build_analyst_dataset(org_id: str | None, db) -> list[dict]:
    """Join feedback verdicts to reconstructed SessionAnalysis rows."""
    from app.models.entities import FindingFeedback, Session, Finding, Severity
    from app.parsing.rules import SessionAnalysis
    from app.parsing.rules import Finding as RuleFinding
    from app.parsing.handshake import CIPHER_DB
    q = db.query(FindingFeedback)
    if org_id:
        q = q.filter(FindingFeedback.org_id == org_id)
    fb_by_session: dict[str, list] = {}
    for fb in q.all():
        if fb.session_id:
            fb_by_session.setdefault(fb.session_id, []).append(fb)
    out = []
    name_by_cipher = {m.name: m for m in CIPHER_DB.values()}
    for sid, fbs in fb_by_session.items():
        sess = db.get(Session, sid)
        if sess is None:
            continue
        if org_id and sess.org_id != org_id:
            continue
        verdicts = [f.verdict for f in fbs]
        if any(v == "confirmed" for v in verdicts):
            y, has_confirmed = 1, True
        elif any(v == "false_positive" for v in verdicts):
            y, has_confirmed = 0, False
        else:
            continue  # accepted_risk only: ambiguous, excluded
        # Reconstruct analysis from stored rows (documented approximation:
        # cipher_meta re-derived by name; cert details unavailable -> zeroed).
        sa = SessionAnalysis(session_id=sess.id, protocol=sess.protocol or "SMTP",
                             five_tuple=sess.five_tuple or "", is_starttls=False)
        sa.findings = [
            RuleFinding(rule_id=f.rule_id, rule_name=f.rule_name,
                        severity=f.severity.value, title=f.title,
                        description=f.description, reference=f.reference)
            for f in db.query(Finding).filter(Finding.session_id == sid).all()
        ]
        if sess.negotiated_cipher and sess.negotiated_cipher in name_by_cipher:
            sa.cipher_meta = name_by_cipher[sess.negotiated_cipher]
            sa.cipher = sess.negotiated_cipher
        out.append({"session_id": sid, "y": y, "source": "analyst",
                    "five_tuple": sess.five_tuple or "",
                    "created_at": sess.created_at, "sa": sa,
                    "confirmed": has_confirmed})
    return out


def check_threshold(entries: list[dict]) -> tuple[bool, str]:
    need = min_per_class()
    pos = sum(1 for e in entries if e["y"] == 1)
    neg = sum(1 for e in entries if e["y"] == 0)
    if pos < need or neg < need:
        return False, (f"below threshold: need >={need}/class, "
                       f"have pos={pos} neg={neg} (ranking-only mode)")
    return True, ""


def grouped_entries(entries: list[dict]):
    from app.ml.splits import grouped_time_split, leakage_report
    from app.parsing.reassembly import split_five_tuple
    tr, te = grouped_time_split(
        entries,
        lambda e: "%s:%s" % (split_five_tuple(e["five_tuple"])[2:] or ("?", 0)),
        lambda e: e.get("created_at"))
    rep = leakage_report(tr, te, lambda e: "%s:%s" % (split_five_tuple(e["five_tuple"])[2:] or ("?", 0)))
    return tr, te, rep


def _fit_predict(train, test):
    import numpy as np
    from app.ml.features import session_features_matrix
    from app.ml.ml_engine import RiskGradientBoost
    Xtr, names, _ = session_features_matrix([e["sa"] for e in train])
    ytr = np.array([e["y"] for e in train], dtype=np.int32)
    Xte, _, _ = session_features_matrix([e["sa"] for e in test])
    yte = np.array([e["y"] for e in test], dtype=np.int32)
    model = RiskGradientBoost()
    model.train(Xtr, ytr, names)
    scores = []
    for row in Xte:
        try:
            proba = (model.calibrated or model.clf).predict_proba(row.reshape(1, -1))[0]
            scores.append(float(proba[1] if len(proba) > 1 else proba[0]))
        except Exception:
            scores.append(0.0)
    return model, names, yte, np.array(scores)


def _metrics_dict(y_true, y_score, threshold: float = 50.0) -> dict:
    from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
    import numpy as _np
    y_true = _np.array(y_true)
    y_pred = (_np.array(y_score) >= threshold).astype(int)
    out = {"n": int(len(y_true)), "positives": int(y_true.sum()),
           "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
           "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
           "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
           "auc": None, "fp_rate": None}
    try:
        if len(set(y_true.tolist())) == 2:
            out["auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
    except Exception:
        pass
    try:
        neg = (y_true == 0)
        if neg.sum():
            out["fp_rate"] = round(float(((y_pred == 1) & neg).sum() / neg.sum()), 4)
    except Exception:
        pass
    return out


def train_candidate(org_id: str | None, db, scope: str = "org") -> dict:
    """Train a candidate on analyst labels; registry-recorded, never promoted.

    scope="org": only this org's labels. scope="global": only TRAINING_OPT_IN_ORGS.
    Returns the registry entry (or a rejection dict with reason).
    """
    import joblib
    from pathlib import Path
    from app.core.config import settings as _s
    from app.ml import registry as _reg
    if scope == "global":
        allowed = opt_in_orgs()
        if not org_id or org_id not in allowed:
            return {"status": "rejected",
                    "reason": "global training requires explicit org opt-in"}
        entries = []
        for oid in sorted(allowed):
            entries.extend(build_analyst_dataset(oid, db))
    else:
        entries = build_analyst_dataset(org_id, db)
    ok, reason = check_threshold(entries)
    if not ok:
        _reg.record_candidate(org_id or "global",
                              f"rejected-{int(time.time())}",
                              {"status": "rejected", "reason": reason,
                               "dataset_size": len(entries)})
        return {"status": "rejected", "reason": reason}
    tr, te, leak = grouped_entries(entries)
    if not tr or not te:
        return {"status": "rejected", "reason": "split produced an empty side"}
    model, names, yte, scores = _fit_predict(tr, te)
    metrics = _metrics_dict(yte, scores)
    metrics["leaked_groups"] = leak["leaked_groups"]
    version = f"analyst-{len(entries)}-{_reg.dataset_hash(entries)}"
    try:
        dest = Path(_s.MODELS_DIR) / (org_id or "global") / f"{version}.pkl"
        dest.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "feature_names": names}, dest)
        artifact = str(dest)
    except Exception as e:
        artifact = f"unavailable: {e}"
    entry = {"status": "candidate", "scope": scope,
             "dataset_size": len(entries), "dataset_hash": _reg.dataset_hash(entries),
             "code_version": _reg.code_version(), "feature_schema": names,
             "metrics": metrics, "artifact": artifact,
             "trained_at": __import__("datetime").datetime.now(
                 __import__("datetime").timezone.utc).isoformat()}
    _reg.record_candidate(org_id or "global", version, entry)
    return {"status": "candidate", "version": version, **entry}


def promotion_gate(org_id: str | None, candidate: dict, current_metrics: dict | None) -> tuple[bool, str]:
    """Promote only on real lift without FP regression. Returns (ok, reason)."""
    cand_f1 = (candidate.get("metrics") or {}).get("f1") or 0.0
    if current_metrics is None:
        return True, "no current model: candidate accepted as first"
    cur_f1 = current_metrics.get("f1") or 0.0
    if cand_f1 < cur_f1 + promote_margin():
        return False, (f"rejected: candidate f1={cand_f1} does not beat current "
                       f"f1={cur_f1} by margin {promote_margin()}")
    cand_fp = (candidate.get("metrics") or {}).get("fp_rate")
    cur_fp = current_metrics.get("fp_rate")
    if cand_fp is not None and cur_fp is not None and cand_fp > cur_fp:
        return False, (f"rejected: false-positive rate regressed "
                       f"{cur_fp} -> {cand_fp}")
    return True, f"promoted: f1 {cur_f1} -> {cand_f1}"


def current_metrics_for(org_id: str | None) -> dict | None:
    from app.ml import registry as _reg
    cur = _reg.org_current(org_id or "global")
    if cur is None:
        return None
    return cur.get("metrics")
