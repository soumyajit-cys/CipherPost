"""Phase 1 Task 7: eval harness sanity (no fabricated real data)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_empty_manifest_ok(tmp_path):
    from scripts.eval_real import eval_manifest
    mp = tmp_path / "manifest.json"
    mp.write_text('{"version": 1, "captures": []}')
    rep = eval_manifest(mp)
    assert rep["captures"] == 0
    assert rep["misses"] == []


def test_harness_detects_miss_on_fixture(tmp_path):
    # Uses an existing synthetic fixture with an intentionally wrong label to
    # prove the harness reports misses (test-only label, not committed data).
    import json
    from scripts.eval_real import eval_manifest
    mp = tmp_path / "manifest.json"
    mp.write_text(json.dumps({
        "version": 1,
        "captures": [{
            "pcap": "fake.pcap",
            "source": "test",
            "license": "test-only",
            "expected_findings": [
                {"rule_id": "nonexistent-rule-xyz", "session": "0", "present": True}
            ],
        }],
    }))
    # Point pcap at a real fixture via symlink
    import pathlib
    real = pathlib.Path("tests/fixtures/smtp_tls12_starttls.pcap").resolve()
    (tmp_path / "fake.pcap").symlink_to(real)
    rep = eval_manifest(mp, base_dir=tmp_path)
    assert rep["sessions_total"] >= 1
    assert any(m["rule_id"] == "nonexistent-rule-xyz" for m in rep["misses"])


def test_diff_tshark_runs_or_skips():
    from scripts.diff_tshark import diff_one, have_tshark
    import pathlib
    p = pathlib.Path("tests/fixtures/imap_starttls_strip.pcap")
    res = diff_one(p)
    assert "pcap" in res
    assert "disagreements" in res
    assert isinstance(have_tshark(), bool)
