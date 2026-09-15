"""
MTA-STS / DANE awareness — documented capability stub.

What this *would* do in a DNS-capable deployment: for each observed mail
domain, fetch `_mta-sts.<domain>` TXT + `mta-sts.<domain>/.well-known/mta-sts.txt`
(RFC 8461) and TLSA records (RFC 6698/7672, DANE), then flag mismatches such
as "domain publishes MTA-STS enforce but a plaintext session was observed".

Why a stub here: this environment has no DNS resolver library installed
(no dnspython) and lab/demo networks often lack MX/DNS entirely. Faking
verdicts would be worse than reporting "not checked". The interface below is
the contract a future DNS-backed implementation must satisfy, and the API
endpoint reports capability status honestly.
"""
from __future__ import annotations


CAPABILITY = {
    "mta_sts": {"supported": False, "reason": "no DNS resolver available in this deployment"},
    "dane": {"supported": False, "reason": "no DNS resolver available in this deployment"},
}


def check_domain(domain: str) -> dict:
    """Return transport-security posture for a domain (stub: not-checked)."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"domain": domain, "status": "invalid-domain"}
    return {
        "domain": domain,
        "status": "not-checked",
        "mta_sts": {"policy": None, "mode": None, **CAPABILITY["mta_sts"]},
        "dane": {"tlsa_records": [], **CAPABILITY["dane"]},
        "mismatch_findings": [],
        "note": ("Enable by installing dnspython, setting CIPHERPOST_DNS_RESOLVER, "
                 "and implementing check_domain() against RFC 8461 / RFC 7672. "
                 "Until then CipherPost reports not-checked rather than guessing."),
    }


def mismatch_for_session(domain: str, used_tls: bool) -> dict | None:
    """Future hook: compare observed session against published policy.

    Returns a finding-dict when a mismatch is proven, else None. Currently
    always None (no DNS data), by design.
    """
    _ = (domain, used_tls)
    return None
