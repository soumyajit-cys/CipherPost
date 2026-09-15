"""
Certificate inventory + expiry forecasting.

Every analyzed session's leaf certificates are upserted into `tracked_certs`
(keyed by SHA-256 of DER). A periodic sweep (`find_expiring`) returns certs
expiring within a configurable window so operators are alerted *before*
expiry — the rules engine only fires once an expired cert is observed.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta

log = logging.getLogger("cipherpost.proactive.certs")


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def track_session_certs(sa, org_id: str | None, db) -> int:
    """Upsert leaf certs from a SessionAnalysis. Returns certs tracked.

    `db` is a sync SQLAlchemy session (works in Celery + live worker).
    Never raises — tracking must not break analysis persistence.
    """
    try:
        from app.models.entities import TrackedCert
        now = datetime.utcnow()
        n = 0
        for c in (getattr(sa, "certs", None) or []):
            der = getattr(c, "der", b"") or b""
            if not der:
                continue
            fp = fingerprint_der(der)
            # only track leaf (first) certs to keep the inventory meaningful
            if getattr(c, "is_ca", False):
                continue
            row = db.get(TrackedCert, fp)
            if row is None:
                row = TrackedCert(
                    fingerprint=fp, org_id=org_id,
                    subject_cn=getattr(c, "subject_cn", "") or "",
                    issuer_cn=getattr(c, "issuer_cn", "") or "",
                    sans=list(getattr(c, "subject_alt_names", None) or []),
                    not_before=getattr(c, "not_before", None),
                    not_after=getattr(c, "not_after", None),
                    pubkey_alg=getattr(c, "pubkey_alg", "") or "",
                    pubkey_bits=getattr(c, "pubkey_bits", None),
                    signature_alg=getattr(c, "signature_alg", "") or "",
                    is_self_signed=bool(getattr(c, "is_self_signed", False)),
                    chain_result=getattr(sa, "chain_result", "") or "",
                    first_seen=now, last_seen=now, seen_count=1,
                )
                db.add(row)
            else:
                row.last_seen = now
                row.seen_count = (row.seen_count or 0) + 1
                if org_id and not row.org_id:
                    row.org_id = org_id
            n += 1
        return n
    except Exception as e:
        log.debug("cert tracking skipped: %s", e)
        return 0


def find_expiring(org_id: str | None, within_days: int, db,
                  include_expired: bool = True) -> list:
    """Certs expiring within `within_days` (or already expired)."""
    from sqlalchemy import or_
    from app.models.entities import TrackedCert
    now = datetime.utcnow()
    horizon = now + timedelta(days=within_days)
    q = db.query(TrackedCert).filter(TrackedCert.not_after.is_not(None))
    if org_id:
        q = q.filter((TrackedCert.org_id == org_id) | (TrackedCert.org_id.is_(None)))
    if include_expired:
        q = q.filter(TrackedCert.not_after <= horizon)
    else:
        q = q.filter(TrackedCert.not_after > now, TrackedCert.not_after <= horizon)
    return q.order_by(TrackedCert.not_after.asc()).all()


def mark_alerted(db, fingerprints: list[str]) -> None:
    try:
        from app.models.entities import TrackedCert
        now = datetime.utcnow()
        for fp in fingerprints:
            row = db.get(TrackedCert, fp)
            if row is not None:
                row.expiry_alerted_at = now
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
