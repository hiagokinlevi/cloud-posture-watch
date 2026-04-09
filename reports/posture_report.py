"""
Posture Report Generator
=========================
Generates Markdown posture reports from a PostureReport object.

The report includes:
  - Executive summary with risk score
  - Findings breakdown by severity
  - Drift summary (if a baseline was used)
  - Per-finding detail with recommendations
  - Appendix with raw risk flags

Usage
-----
    from reports.posture_report import generate_markdown_report
    from schemas.posture import PostureReport

    report = PostureReport(...)
    markdown = generate_markdown_report(report)
    Path("output/report.md").write_text(markdown)
"""
from datetime import datetime
from pathlib import Path

from schemas.posture import DriftItem, PostureFinding, PostureReport, Severity


# Severity display metadata: (emoji-free label, Markdown badge)
_SEVERITY_LABELS: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _risk_score(report: PostureReport) -> int:
    """
    Compute a simple 0-100 risk score based on finding severity distribution.

    Weights: critical=10, high=5, medium=2, low=1
    Score is capped at 100.
    """
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    raw = sum(weights.get(f.severity.value, 0) for f in report.findings)
    return min(raw, 100)


def _format_finding(finding: PostureFinding, index: int) -> str:
    """Format a single finding as a Markdown section."""
    severity_label = _SEVERITY_LABELS.get(finding.severity.value, finding.severity.value.upper())
    lines = [
        f"### Finding {index}: [{severity_label}] {finding.title}",
        "",
        f"- **Resource:** `{finding.resource_name}` ({finding.resource_type})",
        f"- **Provider:** {finding.provider.value.upper()}",
        f"- **Severity:** {severity_label}",
        f"- **Flag:** `{finding.flag}`",
    ]
    if finding.baseline_control:
        lines.append(f"- **Baseline control:** `{finding.baseline_control}`")
    lines += [
        "",
        "**Recommendation:**",
        "",
        f"> {finding.recommendation}",
        "",
    ]
    return "\n".join(lines)


def _format_drift_item(item: DriftItem, index: int) -> str:
    """Format a single drift item as a Markdown row."""
    return (
        f"| {index} | `{item.resource_name}` | `{item.control}` "
        f"| `{item.expected}` | `{item.actual}` | {item.importance.value} | {item.severity.value.upper()} |"
    )


def generate_markdown_report(report: PostureReport) -> str:
    """
    Generate a full Markdown posture report.

    Args:
        report: A populated PostureReport object.

    Returns:
        Multi-line Markdown string suitable for writing to a .md file.
    """
    risk_score = _risk_score(report)
    counts = report.finding_counts
    assessed_at = report.assessed_at.strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        "# Cloud Posture Assessment Report",
        "",
        f"**Provider:** {report.provider.value.upper()}  ",
        f"**Assessed at:** {assessed_at}  ",
        f"**Run ID:** `{report.run_id}`  ",
        f"**Baseline:** {report.baseline_name or 'None'}  ",
        f"**Total resources assessed:** {report.total_resources}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"**Risk Score: {risk_score}/100**",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| CRITICAL | {counts.get('critical', 0)} |",
        f"| HIGH     | {counts.get('high', 0)} |",
        f"| MEDIUM   | {counts.get('medium', 0)} |",
        f"| LOW      | {counts.get('low', 0)} |",
        f"| INFO     | {counts.get('info', 0)} |",
        "",
    ]

    # Overall posture statement
    if risk_score == 0:
        lines += [
            "> No findings detected. The assessed resources meet the baseline requirements.",
            "",
        ]
    elif risk_score < 20:
        lines += [
            "> Low risk. A small number of improvements are recommended.",
            "",
        ]
    elif risk_score < 50:
        lines += [
            "> Moderate risk. Several controls are missing or misconfigured. "
            "Review HIGH findings promptly.",
            "",
        ]
    else:
        lines += [
            "> **High risk.** Critical or numerous high-severity findings detected. "
            "Immediate remediation is advised.",
            "",
        ]

    # Findings section
    lines += ["---", "", "## Findings", ""]

    critical_high = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    medium_low = [f for f in report.findings if f.severity in (Severity.MEDIUM, Severity.LOW)]
    info = [f for f in report.findings if f.severity == Severity.INFO]

    if not report.findings:
        lines.append("No findings.")
    else:
        if critical_high:
            lines += ["### Critical and High Severity", ""]
            for i, finding in enumerate(critical_high, start=1):
                lines.append(_format_finding(finding, i))

        if medium_low:
            lines += ["### Medium and Low Severity", ""]
            for i, finding in enumerate(medium_low, start=1):
                lines.append(_format_finding(finding, i))

        if info:
            lines += ["### Informational", ""]
            for i, finding in enumerate(info, start=1):
                lines.append(_format_finding(finding, i))

    # Drift section
    if report.drift_items:
        lines += [
            "---",
            "",
            "## Configuration Drift",
            "",
            f"The following resources deviate from baseline **{report.baseline_name}**:",
            "",
            "| # | Resource | Control | Expected | Actual | Importance | Severity |",
            "|---|----------|---------|----------|--------|------------|----------|",
        ]
        for i, item in enumerate(report.drift_items, start=1):
            lines.append(_format_drift_item(item, i))
        lines.append("")

    # Footer
    lines += [
        "---",
        "",
        "_Report generated by [cloud-posture-watch](https://github.com/hiagokinlevi/cloud-posture-watch)_",
    ]

    return "\n".join(lines)


def save_report(report: PostureReport, output_dir: str | Path) -> Path:
    """
    Generate and save a Markdown report to the output directory.

    Args:
        report: A populated PostureReport object.
        output_dir: Directory where the report file will be written.

    Returns:
        Path to the written report file.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"posture_{report.provider.value}_{timestamp}.md"
    report_path = output_path / filename

    markdown = generate_markdown_report(report)
    report_path.write_text(markdown, encoding="utf-8")

    return report_path
