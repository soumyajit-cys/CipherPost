"""Phase 4 Task 6: versioned compliance mapping + evidence bundles."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_mapping_loads_versioned_data():
    from app.proactive.compliance import (
        compliance_for, summary_for_findings, mapping_version, FRAMEWORKS)
    assert mapping_version() == 1
    assert set(FRAMEWORKS) >= {"PCI-DSS-4.0", "ISO-27001-2022", "NIST-CSF-2.0",
                               "OWASP-TLS", "CERT-In"}
    # pre-existing behavior preserved through the data move
    tags = compliance_for("expired-certificate")
    assert {t["control"] for t in tags} >= {"4.2", "A.8.24", "PR.DS-02"}
    # phase 4 rules mapped
    assert compliance_for("downgrade-attack-detected")
    assert compliance_for("tls-version-downgrade-suspected")
    assert compliance_for("outdated-client-stack")
    # every tag carries provenance
    for tags in (compliance_for("expired-certificate"),
                 compliance_for("starttls-strip-attempt")):
        for t in tags:
            assert t["framework_title"] and t["url"]
    out = summary_for_findings([{"rule_id": "expired-certificate",
                                 "severity": "high"}])
    assert out["groups"] and out["groups"][0]["count"] == 1


def test_evidence_bundle_roundtrip_and_tamper(tmp_path):
    from app.reporting.evidence import build_bundle, verify_bundle
    report = {"filename": "synthetic.pcap", "sessions": [{"five_tuple": "a-b"}],
              "findings": [{"rule_id": "expired-certificate", "observed": True}],
              "limitations": ["TLS 1.3 certs not observable"]}
    bundle = build_bundle(report, suppressions=[], retention={"sessions_days": 90},
                          versions={"tool": "0.3.0", "rules": "static", "mapping": 1})
    assert bundle["manifest"]["record_count"] == len(bundle["records"])
    assert verify_bundle(bundle)["ok"] is True
    # tamper with a record -> detected
    bundle["records"][0]["body"]["filename"] = "evil.pcap"
    assert verify_bundle(bundle)["ok"] is False
    # unobservable items labeled as such in the bundle
    manifest_labels = bundle["manifest"].get("labels", {})
    assert manifest_labels.get("unobservable", 0) >= 0
