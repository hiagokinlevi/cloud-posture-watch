"""
JSON Posture Report Serializer
================================
Serializes a PostureReport to a structured JSON document suitable for:
  - CI/CD pipeline integration (exit-code based gate + JSON artifact)
  - Downstream SIEM ingestion
  - Dashboard tooling that reads structured data
  - Archiving for historical posture comparison

Output schema:
  {
    "schema_version": "1.0",
    "run_id": "...",
    "provider": "aws",
    "assessed_at": "2026-04-06T12:00:00Z",
    "baseline_name": "standard",
    "total_resources": 12,
    "risk_score": 35,
    "finding_counts": {"critical": 0, "high": 2, "medium": 1, "low": 3, "info": 0},
    "findings": [ { ...PostureFinding fields... } ],
    "drift_items": [ { ...DriftItem fields... } ]
  }

Usage:
    from reports.posture_report_json import generate_json_report, save_json_report

    json_str = generate_json_report(report)
    path = save_json_report(report, "./output")
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reports.posture_report_schema import JSON_SCHEMA_ID, SCHEMA_VERSION
from schemas.posture import DriftItem, PostureFinding, PostureReport
from schemas.risk import SEVERITY_WEIGHTS, calculate_risk_score, classify_risk_score


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _finding_to_dict(finding: PostureFinding) -> dict[str, Any]:
    return {
        "provider":          finding.provider.value,
        "resource_type":     finding.resource_type,
        "resource_name":     finding.resource_name,
        "severity":          finding.severity.value,
        "flag":              finding.flag,
        "title":             finding.title,
        "recommendation":    finding.recommendation,
        "baseline_name":     finding.baseline_name,
        "baseline_control":  finding.baseline_control,
    }


def _drift_to_dict(item: DriftItem) -> dict[str, Any]:
    return {
        "provider":      item.provider.value,
        "resource_type": item.resource_type,
        "resource_name": item.resource_name,
        "baseline_name": item.baseline_name,
        "control":       item.control,
        "expected":      item.expected,
        "actual":        item.actual,
        "importance":    item.importance.value,
        "severity":      item.severity.value,
    }


def _risk_score(report: PostureReport) -> int:
    """Shared 0-100 posture risk score."""
    return calculate_risk_score(report.findings)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_json_report(report: PostureReport, indent: int = 2) -> str:
    """
    Serialize a PostureReport to a structured JSON string.

    Args:
        report:  A populated PostureReport object.
        indent:  JSON indentation level (default 2). Pass 0 for compact output.

    Returns:
        JSON string.
    """
    assessed_at_str = report.assessed_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    risk_score = _risk_score(report)
    risk_band = classify_risk_score(risk_score)

    doc: dict[str, Any] = {
        "$schema":          JSON_SCHEMA_ID,
        "schema_version":   SCHEMA_VERSION,
        "run_id":           report.run_id,
        "provider":         report.provider.value,
        "assessed_at":      assessed_at_str,
        "baseline_name":    report.baseline_name,
        "total_resources":  report.total_resources,
        "risk_score":       risk_score,
        "risk_level":       risk_band.name,
        "risk_model":       {
            "max_score":        100,
            "severity_weights": dict(SEVERITY_WEIGHTS),
        },
        "finding_counts":   report.finding_counts,
        "findings":         [_finding_to_dict(f) for f in report.findings],
        "drift_items":      [_drift_to_dict(d) for d in report.drift_items],
    }

    return json.dumps(doc, indent=indent if indent > 0 else None, ensure_ascii=False)


def save_json_report(report: PostureReport, output_dir: str | Path) -> Path:
    """
    Generate and save a JSON report to the output directory.

    Args:
        report:     A populated PostureReport object.
        output_dir: Directory where the JSON file will be written.

    Returns:
        Path to the written JSON file.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"posture_{report.provider.value}_{timestamp}.json"
    report_path = output_path / filename

    json_str = generate_json_report(report)
    report_path.write_text(json_str, encoding="utf-8")

    return report_path
