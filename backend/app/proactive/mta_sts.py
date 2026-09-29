"""MTA-STS (RFC 8461) + DANE (RFC 6698/7672) checks via dnspython.

Honest statuses only: ok, not-published, misconfigured, dns-error,
dnssec-failed, not-checked (only when DNS is disabled). Nothing is guessed:
unsigned TLSA data is reported `insecure` and never treated as a DANE signal;
DNS failures never raise into the analysis path (they become `dns-error`).

DNSSEC trust model (documented subset): TLSA RRSIGs are validated
cryptographically with dnspython against the zone DNSKEY, which must match the
configured trust anchor (CIPHERPOST_DNSSEC_TRUST_ANCHOR, base64 DER). Without
an anchor, signed data cannot be trusted either -> `dnssec-failed`. Full
root-chain validation is follow-up work; production should additionally point
at a validating resolver.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import re
import threading
import time
from typing import Any

log = logging.getLogger("cipherpost.proactive.mta_sts")

CAPABILITY = {
    "mta_sts": {"supported": True, "reason": "dnspython-backed checks (RFC 8461)"},
    "dane": {"supported": True, "reason": "dnspython-backed checks (RFC 7672, anchor-pinned DNSSEC)"},
}

_MTA_STS_TXT_RE = re.compile(r"v=STSv1;\s*id=([^;\s]+)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Bounded TTL cache (never blocks analysis on DNS)
# --------------------------------------------------------------------------

class TTLCache:
    def __init__(self, max_entries: int = 512):
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str):
        now = time.time()
        with self._lock:
            hit = self._data.get(key)
            if hit is None:
                return None
            exp, val = hit
            if exp < now:
                self._data.pop(key, None)
                return None
            return val

    def put(self, key: str, value: Any, ttl: float) -> None:
        if ttl <= 0:
            return
        with self._lock:
            if len(self._data) >= self.max_entries:
                # evict ~10% oldest expiries
                for k in sorted(self._data, key=lambda k: self._data[k][0])[: max(1, self.max_entries // 10)]:
                    self._data.pop(k, None)
            self._data[key] = (time.time() + ttl, value)


_CACHE = TTLCache()


def _cache() -> TTLCache:
    from app.core.config import settings as _s
    _CACHE.max_entries = int(getattr(_s, "DNS_CACHE_MAX", 512) or 512)
    return _CACHE


# --------------------------------------------------------------------------
# Resolver
# --------------------------------------------------------------------------

def _resolver():
    import dns.resolver
    from app.core.config import settings as _s
    r = dns.resolver.Resolver(configure=False)
    nameserver = (getattr(_s, "DNS_RESOLVER", None) or "").strip()
    if nameserver:
        r.nameservers = [nameserver]
    else:
        r.nameservers = ["127.0.0.53", "127.0.0.1", "8.8.8.8"]
    timeout = float(getattr(_s, "DNS_TIMEOUT_SECONDS", 5.0) or 5.0)
    r.timeout = timeout
    r.lifetime = timeout
    try:
        import dns.flags
        r.use_edns(0, dns.flags.DO, 4096)
    except Exception:
        pass
    return r


def _query(name: str, rdtype: str):
    """DNS query with TTL cache. Returns (answer, min_ttl) or raises."""
    import dns.resolver
    key = f"{rdtype}:{name.lower()}"
    hit = _cache().get(key)
    if hit is not None:
        return hit
    res = _resolver()
    try:
        ans = res.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        raise _NoData(str(e))
    rrs = list(ans)
    ttl = min([getattr(r, "ttl", 300) for r in rrs] + [300])
    _cache().put(key, (rrs, ttl), min(ttl, 3600))
    return rrs, ttl


class _NoData(Exception):
    pass


def _is_dns_disabled() -> bool:
    # not-checked only when the operator never configured DNS at all AND the
    # default path is unusable. dnspython is installed, so checks run whenever
    # a resolver answers; total failure surfaces as dns-error, not not-checked.
    return False


# --------------------------------------------------------------------------
# MTA-STS (RFC 8461)
# --------------------------------------------------------------------------

def _fetch_mta_sts(domain: str) -> dict:
    """Resolve MX, _mta-sts TXT, and the HTTPS policy. Never raises."""
    out: dict = {"mx_hosts": [], "txt": None, "policy": None,
                 "mode": None, "max_age": None, "mx_patterns": [],
                 "error": None}
    try:
        rrs, _ttl = _query(domain, "MX")
        mxs = sorted(((r.preference, str(r.exchange).rstrip(".")) for r in rrs))
        out["mx_hosts"] = [h for _, h in mxs]
    except _NoData as e:
        out["error"] = f"no MX: {e}"
        return out
    except Exception as e:
        out["error"] = f"dns-error MX: {e}"
        return out
    try:
        rrs, _ttl = _query(f"_mta-sts.{domain}", "TXT")
        txt = "".join(
            s.decode() if isinstance(s, bytes) else str(s)
            for r in rrs for s in getattr(r, "strings", [str(r)]))
        out["txt"] = txt
    except _NoData:
        return out  # no TXT -> not-published (not an error)
    except Exception as e:
        out["error"] = f"dns-error TXT: {e}"
        return out
    m = _MTA_STS_TXT_RE.search(out["txt"] or "")
    if not m:
        out["error"] = "malformed _mta-sts TXT (missing v=STSv1/id)"
        return out
    policy_id = m.group(1)
    policy, perr = _fetch_policy(domain)
    if perr:
        out["error"] = perr
        return out
    out["policy"] = policy
    out["policy_id"] = policy_id
    for line in policy.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "mode":
            out["mode"] = v.lower()
        elif k == "max_age":
            try:
                out["max_age"] = int(v)
            except ValueError:
                out["error"] = f"malformed max_age: {v!r}"
        elif k == "mx":
            out["mx_patterns"].append(v)
    if out["mode"] not in ("enforce", "testing", "none"):
        out["error"] = f"malformed mode: {out['mode']!r}"
    return out


def _fetch_policy(domain: str) -> tuple[str | None, str | None]:
    """Fetch https://mta-sts.<domain>/.well-known/mta-sts.txt with SSRF guards.

    Returns (policy_text, error). Only https to public IPs, bounded size/time,
    limited redirects, proper cert validation.
    """
    import httpx
    from app.core.config import settings as _s
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    timeout = float(getattr(_s, "MTASTS_HTTPS_TIMEOUT_SECONDS", 8.0) or 8.0)
    max_bytes = int(getattr(_s, "MTASTS_MAX_POLICY_BYTES", 65536) or 65536)
    max_redirects = int(getattr(_s, "MTASTS_MAX_REDIRECTS", 3) or 3)
    try:
        host = f"mta-sts.{domain}"
        _assert_public_https_target(host)
    except ValueError as e:
        return None, f"policy fetch refused: {e}"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False,
                          max_redirects=0, verify=True) as client:
            current = url
            for _ in range(max_redirects + 1):
                resp = client.get(current, headers={"Host": f"mta-sts.{domain}"})
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location", "")
                    current = _safe_redirect(current, loc)
                    if current is None:
                        return None, "policy fetch refused: unsafe redirect"
                    continue
                if resp.status_code != 200:
                    return None, f"policy HTTP {resp.status_code}"
                data = resp.content
                if len(data) > max_bytes:
                    return None, "policy too large"
                ctype = resp.headers.get("content-type", "")
                if "text/plain" not in ctype and ctype:
                    log.debug("mta-sts policy content-type %r (accepted anyway)", ctype)
                return data.decode("utf-8", errors="replace"), None
            return None, "too many redirects"
    except Exception as e:
        return None, f"policy fetch failed: {e}"


def _assert_public_https_target(host: str) -> None:
    import socket
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not infos:
        raise ValueError("no addresses")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise ValueError(f"non-public address {ip}")


def _safe_redirect(current: str, location: str) -> str | None:
    from urllib.parse import urljoin, urlparse
    nxt = urljoin(current, location)
    p = urlparse(nxt)
    if p.scheme != "https":
        return None
    try:
        _assert_public_https_target(p.hostname or "")
    except ValueError:
        return None
    return nxt


# --------------------------------------------------------------------------
# DANE (RFC 6698/7672) with anchor-pinned DNSSEC
# --------------------------------------------------------------------------

def _trust_anchor_key():
    """Configured DNSKEY trust anchor (base64 DER) or None."""
    from app.core.config import settings as _s
    raw = (getattr(_s, "DNSSEC_TRUST_ANCHOR", "") or "").strip()
    if not raw:
        return None
    try:
        import dns.dnssec
        import dns.rdata
        der = base64.b64decode(raw)
        return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                   der, 0, len(der))
    except Exception as e:
        log.warning("bad DNSSEC_TRUST_ANCHOR: %s", e)
        return None


def _fetch_tlsa(mx_host: str) -> dict:
    """Fetch TLSA for _25._tcp.<mx> with DNSSEC awareness. Never raises."""
    import dns.resolver
    name = f"_25._tcp.{mx_host}"
    out: dict = {"records": [], "dnssec": "unknown", "error": None}
    try:
        res = _resolver()
        ans = res.resolve(name, "TLSA", want_dnssec=True)
    except dns.resolver.NXDOMAIN:
        out["dnssec"] = "not-published"
        return out
    except dns.resolver.NoAnswer:
        out["dnssec"] = "not-published"
        return out
    except Exception as e:
        out["error"] = f"dns-error TLSA: {e}"
        return out
    try:
        rrs = list(ans)
        rrsigs = []
        try:
            import dns.name
            import dns.rdataclass
            import dns.rdatatype
            qname = dns.name.from_text(name)
            rrsigs = list(ans.response.find_rrset(
                ans.response.answer, qname, dns.rdataclass.IN,
                dns.rdatatype.RRSIG, dns.rdatatype.TLSA))
        except Exception:
            rrsigs = []
        for r in rrs:
            out["records"].append({
                "usage": r.usage, "selector": r.selector,
                "mtype": r.mtype, "cert": r.cert.hex(),
            })
        if not rrsigs:
            out["dnssec"] = "insecure"  # unsigned: never a DANE signal
            return out
        anchor = _trust_anchor_key()
        if anchor is None:
            out["dnssec"] = "dnssec-failed"
            out["error"] = "signed TLSA but no trust anchor configured"
            return out
        if _validate_rrsig(name, rrs, rrsigs, anchor):
            out["dnssec"] = "secure"
        else:
            out["dnssec"] = "bogus"
            out["error"] = "RRSIG validation failed"
    except Exception as e:
        out["error"] = f"dnssec processing failed: {e}"
        out["dnssec"] = "dnssec-failed"
    return out


def _validate_rrsig(name: str, rrs, rrsigs, anchor) -> bool:
    import dns.dnssec
    import dns.name
    import dns.rrset
    try:
        res = _resolver()
        keyname = dns.name.from_text(name)
        # Walk up to find the DNSKEY rrset (apex of the test/real zone).
        keys = None
        for _ in range(5):
            try:
                keyans = res.resolve(keyname, "DNSKEY", want_dnssec=False)
                keys = list(keyans)
                break
            except Exception:
                try:
                    keyname = keyname.parent()
                except Exception:
                    return False
        if not keys:
            return False
        # The anchor must match a zone key (pinning = trust).
        anchored = any(
            k.to_digestable() == anchor.to_digestable() for k in keys)
        if not anchored:
            return False
        rrset = dns.rrset.from_rdata(dns.name.from_text(name), 300, rrs)
        sigset = dns.rrset.from_rdata(dns.name.from_text(name), 300, rrsigs)
        dns.dnssec.validate(rrset, sigset, {keyname: keys})
        return True
    except Exception as e:
        log.debug("RRSIG validation failed: %s", e)
        return False


def tlsa_matches(record: dict, cert_der: bytes) -> bool:
    """RFC 7672 matching for usage 2/3, selectors 0/1, matching types 0/1/2."""
    import hashlib
    usage, selector, mtype = record["usage"], record["selector"], record["mtype"]
    if usage not in (2, 3):
        return False  # PKIX-EE/TA (0/1) need full chain validation: out of scope
    try:
        if selector == 0:
            data = cert_der
        elif selector == 1:
            from cryptography import x509 as _x509
            cert = _x509.load_der_x509_certificate(cert_der)
            data = cert.public_key().public_bytes(
                __import__("cryptography.hazmat.primitives.serialization",
                           fromlist=["Encoding"]).Encoding.DER,
                __import__("cryptography.hazmat.primitives.serialization",
                           fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo)
        else:
            return False
        if mtype == 0:
            expect = record["cert"]
            return data.hex() == expect.lower()
        elif mtype == 1:
            return hashlib.sha256(data).hexdigest() == record["cert"].lower()
        elif mtype == 2:
            return hashlib.sha512(data).hexdigest() == record["cert"].lower()
    except Exception:
        return False
    return False


# --------------------------------------------------------------------------
# Public contract (backward compatible extension of the stub)
# --------------------------------------------------------------------------

def check_domain(domain: str, refresh: bool = False) -> dict:
    """Transport-security posture for a domain (real checks, cached)."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or "." not in domain or len(domain) > 253:
        return {"domain": domain, "status": "invalid-domain"}
    if refresh:
        for suffix in ("MX", "TXT", "TLSA"):
            _cache()._data.pop(f"{suffix}:{domain}", None)
            _cache()._data.pop(f"{suffix}:_mta-sts.{domain}", None)
    try:
        sts = _fetch_mta_sts(domain)
    except Exception as e:
        log.debug("mta-sts failed for %s: %s", domain, e)
        return {"domain": domain, "status": "dns-error",
                "mta_sts": {"mode": None, "error": str(e)[:200]},
                "dane": {"tlsa_records": [], "dnssec": "unknown"},
                "mismatch_findings": []}
    dane_results: dict[str, dict] = {}
    for mx in (sts.get("mx_hosts") or [])[:8]:
        try:
            dane_results[mx] = _fetch_tlsa(mx)
        except Exception as e:
            dane_results[mx] = {"records": [], "dnssec": "unknown",
                                "error": str(e)[:200]}
    # Overall status: worst honest signal wins.
    status = "not-published"
    mode = sts.get("mode")
    if sts.get("error"):
        err = sts["error"]
        if err.startswith("dns-error"):
            status = "dns-error"
        elif "malformed" in err or "policy" in err:
            status = "misconfigured"
        else:
            status = "dns-error"
    elif mode in ("enforce", "testing", "none"):
        status = "ok" if mode in ("enforce", "testing") else "not-published"
        if mode == "none":
            status = "not-published"
    elif sts.get("txt") is None and not sts.get("mx_hosts"):
        status = "dns-error"
    sec_states = {v.get("dnssec") for v in dane_results.values()}
    if "bogus" in sec_states or "dnssec-failed" in {
            v.get("dnssec") for v in dane_results.values()
            if v.get("error")}:
        if status in ("not-published", "ok"):
            status = "dnssec-failed"
    return {
        "domain": domain,
        "status": status,
        "mta_sts": {
            "mode": mode,
            "max_age": sts.get("max_age"),
            "mx_patterns": sts.get("mx_patterns", []),
            "mx_hosts": sts.get("mx_hosts", []),
            "policy_id": sts.get("policy_id"),
            "error": sts.get("error"),
            "supported": True,
        },
        "dane": {
            "tlsa_records": dane_results,
            "supported": True,
        },
        "mismatch_findings": [],
        "checked_at": time.time(),
    }


def evaluate_session(domain: str, session_info: dict) -> list[dict]:
    """Proven-mismatch findings for an observed session vs published policy.

    session_info: {used_tls: bool, mx_host: str|None, cert_der: bytes|None,
                   cert_ok: bool|None}
    Returns finding dicts (possibly empty). Never raises, never guesses:
    findings require a published enforce policy or validated (secure) TLSA.
    """
    try:
        posture = check_domain(domain)
    except Exception:
        return []
    findings: list[dict] = []
    mode = (posture.get("mta_sts") or {}).get("mode")
    if mode == "enforce":
        if not session_info.get("used_tls"):
            findings.append({
                "rule_id": "mta-sts-enforce-plaintext",
                "severity": "critical",
                "title": f"{domain} publishes MTA-STS enforce but plaintext was observed",
                "domain": domain,
            })
        elif session_info.get("cert_ok") is False:
            findings.append({
                "rule_id": "mta-sts-enforce-bad-cert",
                "severity": "high",
                "title": f"{domain} publishes MTA-STS enforce but the session cert failed validation",
                "domain": domain,
            })
    dane = posture.get("dane") or {}
    for mx, res in (dane.get("tlsa_records") or {}).items():
        if res.get("dnssec") != "secure" or not res.get("records"):
            continue
        if session_info.get("mx_host") and session_info["mx_host"] != mx:
            continue
        cert_der = session_info.get("cert_der")
        if not cert_der:
            continue
        if not any(tlsa_matches(r, cert_der) for r in res["records"]):
            findings.append({
                "rule_id": "dane-tlsa-mismatch",
                "severity": "high",
                "title": f"Observed cert for {mx} does not match validated TLSA records",
                "domain": domain,
                "mx": mx,
            })
    return findings


def mismatch_for_session(domain: str, used_tls: bool) -> dict | None:
    """Back-compat hook: first proven finding for a session, else None."""
    try:
        found = evaluate_session(domain, {"used_tls": bool(used_tls)})
        return found[0] if found else None
    except Exception:
        return None
