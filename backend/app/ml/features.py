"""
Stage 4: Feature extraction from SessionAnalysis → numeric feature vectors.

Each SessionAnalysis is converted to a dict of numeric values suitable for
scikit-learn. The feature set is deliberately compact (15–20 dims) and
documented so that every input dimension is auditable.

IMPORTANT: initial labels come from the deterministic rules engine (not
independent ground truth). This is a known limitation, not independent
validation.
"""
from __future__ import annotations

from app.parsing.rules import SessionAnalysis
from app.parsing.handshake import CIPHER_DB


# Map TLS version byte → numeric rank (higher = more secure)
VERSION_RANK = {
    0x0300: 0,   # SSLv3
    0x0301: 1,   # TLS1.0
    0x0302: 2,   # TLS1.1
    0x0303: 3,   # TLS1.2
    0x0304: 4,   # TLS1.3
}

SEVERITY_SCORE = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def extract_features(sa: SessionAnalysis) -> dict[str, float]:
    """
    Convert a SessionAnalysis into a flat numeric feature dict.
    Keys are stable and intended for model consumption; call sites
    should not depend on the exact feature order.
    """
    feats: dict[str, float] = {}
    # TLS version rank (0-4)
    feats["tls_version_rank"] = VERSION_RANK.get(sa.tls_version, 0)

    # Cipher metadata
    feats["cipher_strength"] = sa.cipher_meta.strength if sa.cipher_meta else 0.0
    feats["key_length"] = float(sa.cipher_meta.key_len) if sa.cipher_meta else 0.0
    feats["pfs"] = float(sa.cipher_meta.pfs) if sa.cipher_meta else 0.0
    feats["cipher_category_aead"] = float(sa.cipher_meta.kind == "aead") if sa.cipher_meta else 0.0
    feats["cipher_category_cbc"] = float(sa.cipher_meta.kind == "cbc") if sa.cipher_meta else 0.0
    feats["cipher_category_stream"] = float(sa.cipher_meta.kind == "stream") if sa.cipher_meta else 0.0

    # Export / null / RC4 flags
    feats["is_export"] = float(sa.cipher_meta.export_class == "export") if sa.cipher_meta else 0.0
    feats["is_null"] = float(sa.cipher_meta.export_class == "null") if sa.cipher_meta else 0.0
    feats["is_rc4"] = float(sa.cipher_meta.export_class == "rc4") if sa.cipher_meta else 0.0

    # Certificate health
    feats["chain_valid"] = float(sa.chain_result == "ok")
    feats["cert_count"] = float(len(sa.certs))

    # Cert chain aggregate health: average days-to-expiry, weakest sig
    if sa.certs:
        valid_certs = [c for c in sa.certs if c.days_remaining is not None]
        feats["cert_min_days_remaining"] = min(c.days_remaining for c in valid_certs) if valid_certs else 0.0
        feats["cert_max_key_bits"] = max(c.pubkey_bits or 0 for c in sa.certs)
        feats["any_weak_signature"] = float(any(c.weak_signature for c in sa.certs))
        feats["any_short_key"] = float(any(c.short_key for c in sa.certs))
        feats["any_self_signed"] = float(any(c.is_self_signed for c in sa.certs))
        feats["any_expired"] = float(any(c.expired for c in sa.certs))
    else:
        feats["cert_min_days_remaining"] = 0.0
        feats["cert_max_key_bits"] = 0.0
        feats["any_weak_signature"] = 0.0
        feats["any_short_key"] = 0.0
        feats["any_self_signed"] = 0.0
        feats["any_expired"] = 0.0

    # Session context
    feats["is_starttls"] = float(sa.is_starttls)
    feats["has_starttls_offer"] = float(getattr(sa, "saw_starttls_offer", False))
    feats["started_tls"] = float(getattr(sa, "started_tls", False))
    feats["tls_bytes"] = min(float(getattr(sa, "tls_bytes", 0)) / 65536.0, 1.0)
    feats["plaintext_bytes"] = min(float(getattr(sa, "plaintext_bytes", 0)) / 65536.0, 1.0)

    # Findings summary (rules-engine derived)
    feats["finding_count"] = float(len(sa.findings))
    feats["max_severity"] = float(
        max((SEVERITY_SCORE.get(f.severity, 0) for f in sa.findings), default=0)
    )
    # Per-rule presence (binary, most important)
    for rule_prefix in [
        "tls-version", "rc4", "export", "non-pfs", "non-aead",
        "self-signed", "untrusted", "expired", "weak-signature", "short-key",
        "starttls-strip", "plaintext-mail", "weak-cipher", "3des",
        "no-tls-on-implicit", "unknown-cipher", "no-pfs-suites",
    ]:
        feats[f"rule_{rule_prefix}"] = float(any(
            f.rule_id.startswith(rule_prefix) for f in sa.findings
        ))
    return feats


FEATURE_NAMES = sorted([
    "tls_version_rank", "cipher_strength", "key_length", "pfs",
    "cipher_category_aead", "cipher_category_cbc", "cipher_category_stream",
    "is_export", "is_null", "is_rc4", "chain_valid", "cert_count",
    "cert_min_days_remaining", "cert_max_key_bits",
    "any_weak_signature", "any_short_key", "any_self_signed", "any_expired",
    "is_starttls", "has_starttls_offer", "started_tls", "tls_bytes",
    "plaintext_bytes", "finding_count", "max_severity",
    "rule_tls-version", "rule_rc4", "rule_export", "rule_non-pfs",
    "rule_non-aead", "rule_self-signed", "rule_untrusted", "rule_expired",
    "rule_weak-signature", "rule_short-key", "rule_starttls-strip",
    "rule_plaintext-mail", "rule_weak-cipher", "rule_3des",
    "rule_no-tls-on-implicit", "rule_unknown-cipher", "rule_no-pfs-suites",
])


def session_features_matrix(analyses: list[SessionAnalysis]):
    """Return (X, feature_names, session_ids) aligned."""
    rows = []
    ids = []
    for sa in analyses:
        rows.append(extract_features(sa))
        ids.append(sa.five_tuple)
    if not rows:
        return [], [], []
    import numpy as np
    names = sorted(rows[0].keys())
    X = np.array([[r.get(n, 0.0) for n in names] for r in rows], dtype=np.float32)
    return X, names, ids
