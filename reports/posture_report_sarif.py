"""
SARIF posture report serializer.

Converts a PostureReport into SARIF 2.1.0 so posture findings can be uploaded
to GitHub Code Scanning or other SARIF-aware platforms.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from schemas.posture import DriftItem, PostureFinding, PostureReport


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_ID = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_NAME = "cloud-posture-watch"
_TOOL_URI = "https://github.com/hiagokinlevi/cloud-posture-watch"
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _slug(value: str) -> str:
    """Return a filesystem-safe token for synthetic SARIF artifact paths."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return slug or "resource"


def _serialize_value(value: Any) -> str:
    """Serialize a value for SARIF messages and properties."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def _finding_artifact_uri(finding: PostureFinding) -> str:
    return (
        f".cloud-posture-findings/{finding.provider.value}/"
        f"{_slug(finding.resource_type)}/{_slug(finding.resource_name)}.json"
    )


def _drift_artifact_uri(item: DriftItem) -> str:
    return (
        f".cloud-posture-findings/{item.provider.value}/"
        f"{_slug(item.resource_type)}/{_slug(item.resource_name)}.json"
    )


def _sarif_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity.lower(), "warning")


def _stable_fingerprint(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]


def _finding_rule(finding: PostureFinding) -> dict[str, Any]:
    level = _sarif_level(finding.severity.value)
    return {
        "id": finding.flag,
        "name": finding.flag,
        "shortDescription": {"text": finding.title},
        "fullDescription": {
            "text": (
                f"{finding.provider.value.upper()} {finding.resource_type} posture finding "
                f"for {finding.resource_name}."
            )
        },
        "help": {"text": finding.recommendation},
        "defaultConfiguration": {"level": level},
        "properties": {
            "provider": finding.provider.value,
            "resource_type": finding.resource_type,
            "severity": finding.severity.value,
            "baseline_name": finding.baseline_name,
            "baseline_control": finding.baseline_control,
        },
    }


def _drift_rule_id(item: DriftItem) -> str:
    return f"DRIFT-{item.control}"


def _drift_rule(item: DriftItem) -> dict[str, Any]:
    level = _sarif_level(item.severity.value)
    return {
        "id": _drift_rule_id(item),
        "name": _drift_rule_id(item),
        "shortDescription": {"text": f"Baseline drift for control '{item.control}'"},
        "fullDescription": {
            "text": (
                f"{item.provider.value.upper()} baseline drift detected on {item.resource_name} "
                f"for control '{item.control}'."
            )
        },
        "help": {
            "text": (
                f"Align {item.resource_name} with baseline '{item.baseline_name}' for "
                f"control '{item.control}'."
            )
        },
        "defaultConfiguration": {"level": level},
        "properties": {
            "provider": item.provider.value,
            "resource_type": item.resource_type,
            "severity": item.severity.value,
            "baseline_name": item.baseline_name,
            "importance": item.importance.value,
        },
    }


def _finding_result(finding: PostureFinding) -> dict[str, Any]:
    fingerprint = _stable_fingerprint(
        finding.provider.value,
        finding.flag,
        finding.resource_type,
        finding.resource_name,
    )
    return {
        "ruleId": finding.flag,
        "level": _sarif_level(finding.severity.value),
        "message": {
            "text": (
                f"{finding.title} on {finding.resource_name} "
                f"({finding.resource_type}). {finding.recommendation}"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _finding_artifact_uri(finding)},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "fullyQualifiedName": (
                            f"{finding.provider.value}/"
                            f"{finding.resource_type}/"
                            f"{finding.resource_name}"
                        ),
                        "name": finding.resource_name,
                        "kind": "resource",
                    }
                ],
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
        },
        "properties": {
            "provider": finding.provider.value,
            "resource_type": finding.resource_type,
            "resource_name": finding.resource_name,
            "severity": finding.severity.value,
            "recommendation": finding.recommendation,
            "baseline_name": finding.baseline_name,
            "baseline_control": finding.baseline_control,
        },
    }


def _drift_result(item: DriftItem) -> dict[str, Any]:
    rule_id = _drift_rule_id(item)
    fingerprint = _stable_fingerprint(
        item.provider.value,
        rule_id,
        item.resource_type,
        item.resource_name,
        item.control,
    )
    return {
        "ruleId": rule_id,
        "level": _sarif_level(item.severity.value),
        "message": {
            "text": (
                f"Baseline drift on {item.resource_name} for control '{item.control}': "
                f"expected {_serialize_value(item.expected)}, found {_serialize_value(item.actual)}."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _drift_artifact_uri(item)},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "fullyQualifiedName": (
                            f"{item.provider.value}/{item.resource_type}/{item.resource_name}"
                        ),
                        "name": item.resource_name,
                        "kind": "resource",
                    }
                ],
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
        },
        "properties": {
            "provider": item.provider.value,
            "resource_type": item.resource_type,
            "resource_name": item.resource_name,
            "baseline_name": item.baseline_name,
            "control": item.control,
            "importance": item.importance.value,
            "severity": item.severity.value,
            "expected": item.expected,
            "actual": item.actual,
        },
    }


def generate_sarif_report(report: PostureReport, indent: int = 2) -> str:
    """Serialize a PostureReport to SARIF 2.1.0 JSON."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        rules.setdefault(finding.flag, _finding_rule(finding))
        results.append(_finding_result(finding))

    for drift_item in report.drift_items:
        rule_id = _drift_rule_id(drift_item)
        rules.setdefault(rule_id, _drift_rule(drift_item))
        results.append(_drift_result(drift_item))

    sarif_document = {
        "$schema": SARIF_SCHEMA_ID,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {
                    "id": f"{report.provider.value}/{report.run_id}",
                },
                "results": results,
                "properties": {
                    "provider": report.provider.value,
                    "run_id": report.run_id,
                    "baseline_name": report.baseline_name,
                    "total_resources": report.total_resources,
                    "assessed_at": report.assessed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            }
        ],
    }

    return json.dumps(sarif_document, indent=indent if indent > 0 else None, ensure_ascii=False)


def save_sarif_report(report: PostureReport, output_dir: str | Path) -> Path:
    """Generate and save a SARIF report in the requested output directory."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"posture_{report.provider.value}_{timestamp}.sarif"
    report_path = output_path / filename

    sarif_str = generate_sarif_report(report)
    report_path.write_text(sarif_str, encoding="utf-8")

    return report_path
