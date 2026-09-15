"""
Compliance framework mapping for rule-engine findings.

Each mapping cites its source. Framework versions move over time — the
`sources` note per framework tells operators what was verified and to
re-check the current version during audits. Mappings are keyed by rule_id
(with `*` wildcard support) and layered at read/report time, so the
deterministic rules engine itself stays framework-free and primary.

Sources consulted:
- PCI SSC, "Payment Card Industry Data Security Standard (PCI DSS) v4.0.1"
  (March 2024): Requirement 4.2 (strong cryptography for PAN in transit
  over open/public networks); 4.2.1 (TLS 1.2+; SSL/early TLS must not be
  used for cardholder data); Appendix A2 (supplemental validation for
  entities still migrating). https://www.pcisecuritystandards.org
- ISO/IEC 27001:2022 Annex A: A.8.20 (networks security), A.8.21
  (security of network services), A.8.24 (use of cryptography).
  Note: 2013 numbering was A.10/A.13 — use 2022 controls for new audits.
- NIST SP 800-52r2 (already the rules' primary reference) + NIST CSF 2.0
  PR.DS-02 ("data-in-transit is protected").
- OWASP TLS Cheat Sheet (2023): cipher/protocol/certificate guidance.
  https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- CERT-In (Indian Computer Emergency Response Team) advisories and
  guidelines on secure TLS configuration, https://www.cert-in.org.in.
  Control labels here are generic — confirm the current CERT-In advisory
  ID applicable to your sector during an audit.
"""
from __future__ import annotations

import fnmatch

FRAMEWORKS = {
    "PCI-DSS-4.0": {
        "title": "PCI DSS v4.0.1",
        "source": "PCI SSC, PCI DSS v4.0.1 (Mar 2024), Requirement 4.2 / 4.2.1",
        "url": "https://www.pcisecuritystandards.org/document_library",
    },
    "ISO-27001-2022": {
        "title": "ISO/IEC 27001:2022 Annex A",
        "source": "ISO/IEC 27001:2022, controls A.8.20 / A.8.21 / A.8.24",
        "url": "https://www.iso.org/standard/27001",
    },
    "NIST-CSF-2.0": {
        "title": "NIST Cybersecurity Framework 2.0",
        "source": "NIST CSF 2.0, PR.DS-02 (data-in-transit protected)",
        "url": "https://doi.org/10.6028/NIST.CSWP.29",
    },
    "OWASP-TLS": {
        "title": "OWASP TLS Cheat Sheet",
        "source": "OWASP Cheat Sheet Series, Transport Layer Security (2023)",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    },
    "CERT-In": {
        "title": "CERT-In TLS guidance",
        "source": "CERT-In advisories/guidelines on secure TLS deployment; confirm current advisory ID",
        "url": "https://www.cert-in.org.in",
    },
}


def _m(framework: str, control: str, note: str = "") -> dict:
    meta = FRAMEWORKS[framework]
    return {"framework": framework, "control": control,
            "framework_title": meta["title"], "note": note, "url": meta["url"]}


# rule_id pattern -> compliance tags
RULE_COMPLIANCE: dict[str, list[dict]] = {
    # --- deprecated protocol versions -------------------------------------
    "tls-version-*": [
        _m("PCI-DSS-4.0", "4.2.1", "TLS 1.2 or higher required; SSL/early TLS prohibited for PAN"),
        _m("ISO-27001-2022", "A.8.24", "Use of cryptography: deprecated protocols violate policy"),
        _m("NIST-CSF-2.0", "PR.DS-02", "Data-in-transit protection requires current TLS"),
        _m("OWASP-TLS", "protocol-versions", "Use TLS 1.2+ only"),
        _m("CERT-In", "tls-configuration", "Disable SSLv2/v3, TLS 1.0/1.1 per current advisory"),
    ],
    # --- weak / export / RC4 / 3DES / non-AEAD bulk ciphers ----------------
    "weak-cipher-suite": [
        _m("PCI-DSS-4.0", "4.2", "Strong cryptography required in transit"),
        _m("ISO-27001-2022", "A.8.24", "Approved cipher suites only"),
        _m("OWASP-TLS", "cipher-suites", "Prefer AEAD suites; no weak ciphers"),
        _m("CERT-In", "tls-configuration", "Disable weak cipher suites"),
    ],
    "export-grade-cipher": [
        _m("PCI-DSS-4.0", "4.2", "Export-grade cryptography is not strong cryptography"),
        _m("ISO-27001-2022", "A.8.24", "Prohibited cipher suites in use"),
        _m("NIST-CSF-2.0", "PR.DS-02", "Weak transport encryption"),
        _m("OWASP-TLS", "cipher-suites", "EXPORT suites must be disabled"),
    ],
    "rc4-cipher": [
        _m("PCI-DSS-4.0", "4.2", "RC4 is not strong cryptography (RFC 7465)"),
        _m("ISO-27001-2022", "A.8.24", "Prohibited cipher in use"),
        _m("OWASP-TLS", "cipher-suites", "RC4 prohibited"),
    ],
    "3des-cipher": [
        _m("PCI-DSS-4.0", "4.2", "3DES provides only ~112-bit effective strength; migrate to AES-GCM"),
        _m("ISO-27001-2022", "A.8.24", "Legacy cipher should be phased out"),
        _m("NIST-CSF-2.0", "PR.DS-02", "SWEET32 (CVE-2016-2183) exposure on long-lived sessions"),
    ],
    "non-aead-bulk-cipher": [
        _m("PCI-DSS-4.0", "4.2", "Prefer authenticated encryption for PAN in transit"),
        _m("OWASP-TLS", "cipher-suites", "Use AEAD suites (GCM/ChaCha20-Poly1305)"),
    ],
    "unknown-cipher-suite": [
        _m("ISO-27001-2022", "A.8.21", "Unreviewed network-service configuration"),
    ],
    # --- forward secrecy ----------------------------------------------------
    "non-pfs-key-exchange": [
        _m("PCI-DSS-4.0", "4.2", "Lack of PFS weakens long-term confidentiality of PAN"),
        _m("ISO-27001-2022", "A.8.24", "Key management: static key exchange discouraged"),
        _m("OWASP-TLS", "cipher-suites", "Prefer ECDHE for forward secrecy"),
    ],
    "client-no-pfs-suites": [
        _m("OWASP-TLS", "cipher-suites", "Clients should offer ECDHE suites"),
        _m("ISO-27001-2022", "A.8.21", "Client configuration review"),
    ],
    # --- certificates ---------------------------------------------------------
    "expired-certificate": [
        _m("PCI-DSS-4.0", "4.2", "Expired certificates break trust validation of encrypted channels"),
        _m("ISO-27001-2022", "A.8.24", "Certificate lifecycle management failure"),
        _m("NIST-CSF-2.0", "PR.DS-02", "Unverifiable transport endpoint"),
    ],
    "certificate-not-yet-valid": [
        _m("ISO-27001-2022", "A.8.24", "Certificate lifecycle / clock-sync issue"),
    ],
    "self-signed-certificate": [
        _m("PCI-DSS-4.0", "4.2", "Self-signed certs are not trusted for PAN transmission"),
        _m("ISO-27001-2022", "A.8.24", "Certificates must chain to a trusted CA"),
        _m("OWASP-TLS", "certificates", "Use publicly trusted CA certificates"),
    ],
    "untrusted-certificate-chain": [
        _m("PCI-DSS-4.0", "4.2", "Untrusted chain defeats MITM protection"),
        _m("ISO-27001-2022", "A.8.24", "Trust anchor management failure"),
        _m("CERT-In", "tls-configuration", "Deploy CA-signed certificates from trusted roots"),
    ],
    "weak-signature-algorithm": [
        _m("PCI-DSS-4.0", "4.2", "SHA-1/MD5 signatures are forgeable (Shattered, CVE-2017-7494)"),
        _m("ISO-27001-2022", "A.8.24", "Approved signature algorithms only (SHA-256+)"),
        _m("OWASP-TLS", "certificates", "SHA-256 minimum"),
    ],
    "short-public-key": [
        _m("PCI-DSS-4.0", "4.2", "RSA < 2048-bit is not strong cryptography"),
        _m("ISO-27001-2022", "A.8.24", "Minimum key lengths not met"),
        _m("NIST-CSF-2.0", "PR.DS-02", "NIST SP 800-57 key-size guidance"),
    ],
    # --- transport policy ------------------------------------------------------
    "plaintext-mail-protocol": [
        _m("PCI-DSS-4.0", "4.2", "PAN must not traverse open networks unencrypted"),
        _m("ISO-27001-2022", "A.8.20", "Network controls must enforce encryption"),
        _m("NIST-CSF-2.0", "PR.DS-02", "Unprotected data in transit (RFC 8314)"),
        _m("CERT-In", "tls-configuration", "Enforce TLS for mail submission/access"),
    ],
    "starttls-strip-attempt": [
        _m("PCI-DSS-4.0", "4.2", "Active downgrade defeats transport encryption"),
        _m("ISO-27001-2022", "A.8.20", "Network attack indicator (STRIPTLS)"),
        _m("NIST-CSF-2.0", "PR.DS-02", "Downgrade-attack exposure; consider MTA-STS/DANE"),
    ],
    "no-tls-on-implicit-port": [
        _m("PCI-DSS-4.0", "4.2", "Implicit-TLS ports must carry TLS (RFC 8314)"),
        _m("ISO-27001-2022", "A.8.21", "Service misconfiguration on secure port"),
    ],
    "tls-handshake-incomplete": [
        _m("ISO-27001-2022", "A.8.20", "Anomalous transport behavior; investigate"),
    ],
    "alpn-not-negotiated": [
        _m("OWASP-TLS", "protocol-versions", "ALPN hygiene on shared ports"),
    ],
}


def compliance_for(rule_id: str) -> list[dict]:
    """Compliance tags for a rule_id (wildcard-aware)."""
    out: list[dict] = []
    for pattern, tags in RULE_COMPLIANCE.items():
        if fnmatch.fnmatch(rule_id, pattern):
            out.extend(tags)
    return out


def summary_for_findings(findings: list[dict], framework: str | None = None) -> dict:
    """Group findings by compliance control. `findings` items need rule_id + severity."""
    groups: dict[str, dict] = {}
    uncovered = 0
    for f in findings:
        tags = compliance_for(f.get("rule_id", ""))
        if framework:
            tags = [t for t in tags if t["framework"] == framework]
        if not tags:
            uncovered += 1
            continue
        for t in tags:
            key = f"{t['framework']}:{t['control']}"
            g = groups.setdefault(key, {"framework": t["framework"],
                                        "control": t["control"], "count": 0,
                                        "severities": {}, "rules": set()})
            g["count"] += 1
            sev = f.get("severity", "info")
            g["severities"][sev] = g["severities"].get(sev, 0) + 1
            g["rules"].add(f.get("rule_id", ""))
    for g in groups.values():
        g["rules"] = sorted(g["rules"])
    return {"frameworks": FRAMEWORKS if not framework else {framework: FRAMEWORKS[framework]},
            "groups": sorted(groups.values(), key=lambda g: -g["count"]),
            "unmapped_findings": uncovered}
