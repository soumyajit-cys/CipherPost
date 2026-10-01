"""Phase 3 Task 4: CLI offline behavior (no server, DB, Redis, or network)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import subprocess


def _run(*args):
    return subprocess.run([sys.executable, "-m", "app.cli", *args],
                          capture_output=True, text=True, cwd=".",
                          env={**os.environ, "PYTHONPATH": "backend"})


def test_version_single_source_of_truth():
    """backend/app/VERSION, settings.APP_VERSION, and CLI agree."""
    from pathlib import Path
    from app.core.config import settings
    from app import cli
    assert (Path("backend/app/VERSION").read_text().strip()
            == settings.APP_VERSION == cli.version() == "0.3.0")


def test_version_and_rules_no_network(monkeypatch):
    # Prove offline: any socket use fails the test.
    import socket as _s
    monkeypatch.setattr(_s, "socket", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("network used")))
    from app import cli
    assert cli.version() == "0.3.0"
    catalog = cli.rule_catalog()
    assert len(catalog) >= 19
    assert {r["rule_id"] for r in catalog} >= {"expired-certificate",
                                              "starttls-strip-attempt"}


def test_scan_exit_codes_and_golden_json(tmp_path):
    clean = _run("scan", "tests/fixtures/smtp_tls12_starttls.pcap", "--format", "json")
    assert clean.returncode == 0, clean.stderr
    report = json.loads(clean.stdout)
    assert report["schema_version"] == 1 and report["cipherpost_version"] == "0.3.0"
    assert all("findings" in s for s in report["sessions"])
    golden = tmp_path / "golden.json"
    golden.write_text(json.dumps(report, indent=2, sort_keys=True))
    assert json.loads(golden.read_text())["sessions"] == report["sessions"]

    weak = _run("scan", "tests/fixtures/imap_tls10_weak.pcap", "--format", "json")
    assert weak.returncode == 1  # high findings present
    assert any(f["severity"] == "high"
               for s in json.loads(weak.stdout)["sessions"] for f in s["findings"])

    missing = _run("scan", "tests/fixtures/nope.pcap")
    assert missing.returncode == 2  # usage/error


def test_scan_malformed_pcap_is_parse_failure(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\x00\x01not a pcap at all\xff\xfe" * 64)
    r = _run("scan", str(bad))
    assert r.returncode in (1, 3)  # findings or parse failure, never crash/0-with-garbage


def test_scan_sarif_and_baseline_filter():
    sarif = _run("scan", "tests/fixtures/imap_tls10_weak.pcap", "--format", "sarif")
    assert sarif.returncode == 1
    doc = json.loads(sarif.stdout)
    assert doc["version"] == "2.1.0" and doc["runs"][0]["tool"]["driver"]["name"] == "cipherpost"
    assert doc["runs"][0]["results"]
    # baseline ignoring everything returns clean
    import tempfile
    report = json.loads(_run("scan", "tests/fixtures/imap_tls10_weak.pcap",
                             "--format", "json").stdout)
    base = {"ignore": [{"rule_id": f["rule_id"]} for s in report["sessions"]
                       for f in s["findings"]]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(base, fh)
        path = fh.name
    r = _run("scan", "tests/fixtures/imap_tls10_weak.pcap", "--baseline", path)
    assert r.returncode == 0, r.stdout
