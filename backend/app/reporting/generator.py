"""
Stage 5: Report generation — JSON, HTML (Jinja2), PDF (WeasyPrint).

Produces both per-analysis and fleet-wide reports from SessionAnalysis + scoring
results. HTML templates are embedded as strings to avoid filesystem dependency.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime
from typing import Any

from jinja2 import Template

from app.parsing.rules import SessionAnalysis, Finding, max_severity
from app.ml.features import SEVERITY_SCORE
from app.parsing.handshake import version_name
from app.ml.ml_engine import ScoringResult, FeatureContribution

SEVERITY_COLORS = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#2563eb", "info": "#6b7280",
}

SUMMARY_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>CipherPost Report</title>
<style>
  body{font-family:system-ui,sans-serif;margin:2em;color:#1a1a2e;background:#fafafa}
  .header{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:1.5em 2em;border-radius:8px;margin-bottom:1.5em}
  h1{margin:0;font-size:1.6em} h2{color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:0.3em}
  table{width:100%;border-collapse:collapse;margin:1em 0}
  th,td{padding:0.6em 0.8em;text-align:left;border-bottom:1px solid #e2e8f0;font-size:0.9em}
  th{background:#f1f5f9;font-weight:600}
  .sev-critical{color:#dc2626;font-weight:700}.sev-high{color:#ea580c;font-weight:600}
  .sev-medium{color:#ca8a04;font-weight:600}.sev-low{color:#2563eb}.sev-info{color:#6b7280}
  .score{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:0.85em}
  .score-good{background:#16a34a}.score-warn{background:#ca8a04}.score-bad{background:#dc2626}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:1.2em;margin-bottom:1em}
  pre{background:#f8fafc;padding:0.8em;border-radius:6px;font-size:0.82em;overflow-x:auto}
  .meta{display:flex;gap:2em;flex-wrap:wrap;margin:1em 0}.meta-item{min-width:140px}
  .meta-label{font-size:0.78em;color:#64748b;text-transform:uppercase;letter-spacing:0.05em}
  .meta-value{font-size:1.1em;font-weight:600;color:#1e3a5f}
  footer{margin-top:2em;padding-top:1em;border-top:1px solid #e2e8f0;color:#64748b;font-size:0.8em}
</style></head>
<body>
<div class="header">
  <h1>CipherPost — Cryptographic Posture Report</h1>
  <p>Generated {{ timestamp }} | {{ filename }}</p>
</div>
<div class="card"><div class="meta">
  <div class="meta-item"><div class="meta-label">Sessions</div><div class="meta-value">{{ total_sessions }}</div></div>
  <div class="meta-item"><div class="meta-label">Total Findings</div><div class="meta-value">{{ total_findings }}</div></div>
  <div class="meta-item"><div class="meta-label">Critical</div><div class="meta-value" style="color:#dc2626">{{ critical }}</div></div>
  <div class="meta-item"><div class="meta-label">High</div><div class="meta-value" style="color:#ea580c">{{ high }}</div></div>
  <div class="meta-item"><div class="meta-label">Medium</div><div class="meta-value" style="color:#ca8a04">{{ medium }}</div></div>
  <div class="meta-item"><div class="meta-label">Fleet Score</div><div class="meta-value"><span class="score {{ fleet_score_class }}">{{ fleet_score }}/100</span></div></div>
</div></div>
<h2>Sessions</h2>
<table><thead><tr><th>Protocol</th><th>Five-tuple</th><th>TLS Version</th><th>Cipher</th><th>Chain</th><th>Posture</th><th>Anomaly</th><th>Max Severity</th></tr></thead>
<tbody>{% for s in sessions %}<tr>
  <td>{{ s.protocol }}</td><td style="font-size:0.82em">{{ s.five_tuple }}</td>
  <td>{{ s.tls_version or '—' }}</td><td style="font-size:0.82em">{{ s.cipher or '—' }}</td>
  <td>{{ s.chain_result }}</td>
  <td><span class="score {{ s.score_class }}">{{ s.posture }}/100</span></td>
  <td>{{ '⚠' if s.anomaly else '—' }}</td>
  <td><span class="sev-{{ s.max_severity }}">{{ s.max_severity or 'none' }}</span></td>
</tr>{% endfor %}</tbody></table>
{% if findings %}
<h2>Findings (severity-sorted)</h2>
<table><thead><tr><th>Severity</th><th>Session</th><th>Rule</th><th>Title</th><th>Description</th></tr></thead>
<tbody>{% for f in findings %}<tr>
  <td><span class="sev-{{ f.severity }}">{{ f.severity }}</span></td>
  <td style="font-size:0.82em">{{ f.session }}</td>
  <td>{{ f.rule_id }}</td><td>{{ f.title }}</td>
  <td style="font-size:0.82em">{{ f.description }}</td>
</tr>{% endfor %}</tbody></table>
{% endif %}
{% if shap_details %}
<h2>SHAP Explanations (top sessions)</h2>
{% for sd in shap_details %}
<div class="card"><strong>{{ sd.name }}</strong> — posture={{ sd.score }}/100
{% if sd.contributions %}<pre>{% for c in sd.contributions %}{{ '%+6.3f' | format(c.impact) }}  {{ c.feature }}  = {{ c.value }}\n{% endfor %}</pre>{% endif %}
</div>
{% endfor %}
{% endif %}
<footer>CipherPost v0.1.0 — AI-assisted passive network forensic analysis | Rules: NIST SP 800-52r2 / OWASP</footer>
</body></html>""")


def build_report_data(analyses: list[SessionAnalysis],
                      scores: list[ScoringResult] | None = None,
                      filename: str = "unknown.pcap") -> dict[str, Any]:
    """Build structured JSON report dict."""
    all_findings: list[dict] = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in analyses:
        for f in a.findings:
            all_findings.append({
                "rule_id": f.rule_id, "severity": f.severity,
                "title": f.title, "description": f.description,
                "reference": f.reference, "session": a.five_tuple,
            })
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    all_findings.sort(key=lambda x: SEVERITY_SCORE.get(x["severity"], 0), reverse=True)
    session_rows = []
    shap_details = []
    for i, a in enumerate(analyses):
        s = scores[i] if scores and i < len(scores) else None
        posture = s.risk.posture_score if s else 0
        session_rows.append({
            "five_tuple": a.five_tuple, "protocol": a.protocol,
            "tls_version": version_name(a.tls_version), "cipher": a.cipher,
            "chain_result": a.chain_result, "posture": int(posture),
            "anomaly": bool(s.anomaly.is_anomaly) if s else False,
            "max_severity": max_severity(a.findings) or "none",
        })
        if s and s.shap_contributions:
            shap_details.append({
                "name": a.five_tuple, "score": posture,
                "contributions": [{"feature": c.feature, "value": c.value, "impact": c.impact}
                                  for c in s.shap_contributions[:10]]
            })
    fleet_score = sum(r["posture"] for r in session_rows) / max(1, len(session_rows))
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "filename": filename,
        "total_sessions": len(analyses),
        "total_findings": len(all_findings),
        "severity_counts": sev_counts,
        "fleet_posture_score": int(fleet_score),
        "sessions": session_rows,
        "findings": all_findings,
        "shap_details": shap_details,
    }


def generate_json(analyses, scores=None, filename="pcap") -> str:
    data = build_report_data(analyses, scores, filename)
    return json.dumps(data, indent=2)


def generate_html(analyses, scores=None, filename="pcap") -> str:
    data = build_report_data(analyses, scores, filename)
    sessions_for_template = []
    for s in data["sessions"]:
        sc = "score-good" if s["posture"] < 40 else ("score-warn" if s["posture"] < 70 else "score-bad")
        sessions_for_template.append({**s, "score_class": sc})
    findings_for_template = data["findings"]
    fleet_score = data["fleet_posture_score"]
    fleet_class = "score-good" if fleet_score < 40 else ("score-warn" if fleet_score < 70 else "score-bad")
    return SUMMARY_TEMPLATE.render(
        timestamp=data["generated_at"], filename=filename,
        total_sessions=data["total_sessions"], total_findings=data["total_findings"],
        critical=data["severity_counts"].get("critical", 0),
        high=data["severity_counts"].get("high", 0),
        medium=data["severity_counts"].get("medium", 0),
        fleet_score=fleet_score, fleet_score_class=fleet_class,
        sessions=sessions_for_template, findings=findings_for_template,
        shap_details=data["shap_details"],
    )


def generate_pdf(html_content: str, output_path: str) -> str | None:
    """Generate PDF from HTML using WeasyPrint. Returns path or None if unavailable."""
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(output_path)
        return output_path
    except ImportError:
        return None
    except Exception:
        return None
