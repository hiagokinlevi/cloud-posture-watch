"""
HTML Posture Report Generator
================================
Generates a self-contained, single-file HTML posture report from a
PostureReport object. The HTML is styled inline (no external CSS or JS
dependencies) so that it renders correctly in any browser and can be
emailed as an attachment or uploaded to an S3 static site.

Report sections:
  - Header: run metadata (provider, baseline, timestamp, run ID)
  - Executive summary: risk score gauge and severity breakdown table
  - Findings: per-finding cards with severity badge, recommendation, resource
  - Drift: table of baseline deviations
  - Footer

Usage:
    from reports.posture_report_html import generate_html_report, save_html_report

    html = generate_html_report(report)
    path = save_html_report(report, "./output")
"""
from __future__ import annotations

import html as html_lib
from datetime import datetime, timezone
from pathlib import Path

from schemas.posture import DriftItem, PostureFinding, PostureReport, Severity
from schemas.risk import calculate_risk_score, classify_risk_score


# ---------------------------------------------------------------------------
# Style constants (inline CSS, no external dependencies)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#2ecc71",
    "info":     "#3498db",
}

_SEVERITY_TEXT_COLORS: dict[str, str] = {
    "critical": "#ffffff",
    "high":     "#ffffff",
    "medium":   "#333333",
    "low":      "#ffffff",
    "info":     "#ffffff",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #f5f5f5; color: #333; line-height: 1.6; }
.container { max-width: 1000px; margin: 0 auto; padding: 24px; }
header { background: #1a1a2e; color: #fff; padding: 24px 32px; border-radius: 8px 8px 0 0; }
header h1 { font-size: 1.5rem; font-weight: 600; }
header .meta { font-size: 0.85rem; opacity: 0.75; margin-top: 6px; }
.section { background: #fff; padding: 24px 32px; margin-top: 16px;
           border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
h2 { font-size: 1.15rem; font-weight: 600; margin-bottom: 16px;
     padding-bottom: 8px; border-bottom: 2px solid #eee; }
h3 { font-size: 1rem; font-weight: 600; margin-bottom: 8px; }
.risk-score { font-size: 3rem; font-weight: 700; }
.risk-label { font-size: 0.9rem; color: #666; margin-top: 4px; }
.summary-grid { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 16px; }
.sev-card { flex: 1; min-width: 100px; padding: 12px 16px;
            border-radius: 6px; text-align: center; }
.sev-card .count { font-size: 2rem; font-weight: 700; }
.sev-card .label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
                   letter-spacing: 0.05em; }
.finding { border: 1px solid #e0e0e0; border-radius: 6px; padding: 16px;
           margin-bottom: 12px; }
.finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px;
         font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
         letter-spacing: 0.04em; }
.finding-title { font-weight: 600; font-size: 0.95rem; }
.finding-meta { font-size: 0.82rem; color: #666; margin-bottom: 8px; }
.finding-meta span { margin-right: 16px; }
.rec { background: #f8f9fa; border-left: 3px solid #3498db; padding: 10px 14px;
       font-size: 0.85rem; border-radius: 0 4px 4px 0; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: #f8f9fa; text-align: left; padding: 8px 12px; font-weight: 600;
     border-bottom: 2px solid #ddd; }
td { padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:last-child td { border-bottom: none; }
code { background: #f0f0f0; padding: 1px 6px; border-radius: 3px;
       font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.82rem; }
footer { text-align: center; padding: 20px; font-size: 0.78rem; color: #999; }
.empty { color: #999; font-style: italic; }
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(text: str) -> str:
    """HTML-escape a string."""
    return html_lib.escape(str(text), quote=True)


def _badge(severity: str) -> str:
    bg  = _SEVERITY_COLORS.get(severity, "#999")
    col = _SEVERITY_TEXT_COLORS.get(severity, "#fff")
    return (
        f'<span class="badge" style="background:{bg};color:{col};">'
        f'{_e(severity.upper())}</span>'
    )


def _risk_score(report: PostureReport) -> int:
    return calculate_risk_score(report.findings)


def _risk_color(score: int) -> str:
    if score == 0:
        return "#27ae60"
    elif score < 20:
        return "#2ecc71"
    elif score < 50:
        return "#f39c12"
    else:
        return "#c0392b"


# ---------------------------------------------------------------------------
# Section generators
# ---------------------------------------------------------------------------

def _html_header(report: PostureReport, assessed_at: str) -> str:
    return f"""
<header>
  <h1>Cloud Posture Assessment Report</h1>
  <div class="meta">
    Provider: <strong>{_e(report.provider.value.upper())}</strong> &nbsp;|&nbsp;
    Baseline: <strong>{_e(report.baseline_name or 'None')}</strong> &nbsp;|&nbsp;
    Assessed: <strong>{_e(assessed_at)}</strong> &nbsp;|&nbsp;
    Run ID: <code>{_e(report.run_id)}</code>
  </div>
</header>
"""


def _html_summary(report: PostureReport) -> str:
    score = _risk_score(report)
    risk_band = classify_risk_score(score)
    counts = report.finding_counts
    color = _risk_color(score)

    cards = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        bg  = _SEVERITY_COLORS.get(sev, "#999")
        col = _SEVERITY_TEXT_COLORS.get(sev, "#fff")
        n   = counts.get(sev, 0)
        cards += (
            f'<div class="sev-card" style="background:{bg};color:{col};">'
            f'<div class="count">{n}</div>'
            f'<div class="label">{sev.upper()}</div>'
            f'</div>'
        )

    return f"""
<div class="section">
  <h2>Executive Summary</h2>
  <div>
    <div class="risk-score" style="color:{color};">{score}<span style="font-size:1rem;color:#666;">/100</span></div>
    <div class="risk-label">{_e(risk_band.name.upper())}: {_e(risk_band.summary)}</div>
    <div style="font-size:0.82rem;color:#999;margin-top:4px;">
      Total resources assessed: <strong>{report.total_resources}</strong>
    </div>
  </div>
  <div class="summary-grid">{cards}</div>
</div>
"""


def _html_findings(report: PostureReport) -> str:
    if not report.findings:
        return """
<div class="section">
  <h2>Findings</h2>
  <p class="empty">No findings detected.</p>
</div>
"""
    cards = ""
    for finding in sorted(report.findings, key=lambda f: ["critical","high","medium","low","info"].index(f.severity.value)):
        meta = (
            f'<span>Resource: <code>{_e(finding.resource_name)}</code></span>'
            f'<span>Type: <code>{_e(finding.resource_type)}</code></span>'
            f'<span>Provider: {_e(finding.provider.value.upper())}</span>'
            f'<span>Flag: <code>{_e(finding.flag)}</code></span>'
        )
        if finding.baseline_control:
            meta += f'<span>Control: <code>{_e(finding.baseline_control)}</code></span>'

        cards += f"""
<div class="finding">
  <div class="finding-header">
    {_badge(finding.severity.value)}
    <span class="finding-title">{_e(finding.title)}</span>
  </div>
  <div class="finding-meta">{meta}</div>
  <div class="rec"><strong>Recommendation:</strong> {_e(finding.recommendation)}</div>
</div>
"""
    return f"""
<div class="section">
  <h2>Findings</h2>
  {cards}
</div>
"""


def _html_drift(report: PostureReport) -> str:
    if not report.drift_items:
        return ""

    rows = ""
    for item in report.drift_items:
        rows += (
            f"<tr>"
            f"<td><code>{_e(item.resource_name)}</code></td>"
            f"<td><code>{_e(item.control)}</code></td>"
            f"<td><code>{_e(str(item.expected))}</code></td>"
            f"<td><code>{_e(str(item.actual))}</code></td>"
            f"<td>{_e(item.importance.value)}</td>"
            f"<td>{_badge(item.severity.value)}</td>"
            f"</tr>"
        )

    return f"""
<div class="section">
  <h2>Configuration Drift</h2>
  <p style="font-size:0.85rem;color:#666;margin-bottom:12px;">
    Resources deviating from baseline <strong>{_e(report.baseline_name or '')}</strong>:
  </p>
  <table>
    <thead>
      <tr>
        <th>Resource</th><th>Control</th><th>Expected</th>
        <th>Actual</th><th>Importance</th><th>Severity</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_html_report(report: PostureReport) -> str:
    """
    Generate a self-contained HTML posture report.

    Args:
        report: A populated PostureReport object.

    Returns:
        Complete HTML string (no external dependencies).
    """
    assessed_at = report.assessed_at.strftime("%Y-%m-%d %H:%M UTC")

    body = (
        _html_header(report, assessed_at)
        + _html_summary(report)
        + _html_findings(report)
        + _html_drift(report)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloud Posture Report — {_e(report.provider.value.upper())} — {_e(assessed_at)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="container">
    {body}
    <footer>
      Generated by
      <a href="https://github.com/hiagokinlevi/cloud-posture-watch">cloud-posture-watch</a>
      &mdash; CC BY 4.0 &mdash; {_e(assessed_at)}
    </footer>
  </div>
</body>
</html>
"""


def save_html_report(report: PostureReport, output_dir: str | Path) -> Path:
    """
    Generate and save an HTML report to the output directory.

    Args:
        report:     A populated PostureReport object.
        output_dir: Directory where the HTML file will be written.

    Returns:
        Path to the written HTML file.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"posture_{report.provider.value}_{timestamp}.html"
    report_path = output_path / filename

    html = generate_html_report(report)
    report_path.write_text(html, encoding="utf-8")

    return report_path
