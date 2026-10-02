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
import json
import logging
from pathlib import Path

log = logging.getLogger("cipherpost.proactive.compliance")

_MAPPING_VERSION = 1


def _load_mapping() -> dict:
    """Load versioned mapping data (single source of truth for tags)."""
    path = Path(__file__).resolve().parent / "compliance_data" / "mapping-v1.json"
    try:
        doc = json.loads(path.read_text())
    except Exception as e:
        log.warning("compliance mapping missing (%s): tags will be empty", e)
        return {"frameworks": {}, "rules": {}}
    return doc


_DOC = _load_mapping()
FRAMEWORKS: dict = _DOC.get("frameworks", {})
RULE_COMPLIANCE: dict[str, list[dict]] = _DOC.get("rules", {})


def mapping_version() -> int:
    return int(_DOC.get("mapping_version", 0))


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
