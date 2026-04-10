"""
Stable JSON schema contract for posture report exports.

The schema is dependency-free so CI jobs and offline review environments can
inspect the report contract without installing jsonschema.
"""
from __future__ import annotations

from typing import Any

SCHEMA_VERSION = "1.0"
JSON_SCHEMA_ID = (
    "https://github.com/hiagokinlevi/cloud-posture-watch/"
    "schemas/posture-report-v1.json"
)
JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"

SEVERITIES = ("critical", "high", "medium", "low", "info")
PROVIDERS = ("aws", "azure", "gcp")
IMPORTANCE_LEVELS = ("required", "recommended", "informational")

POSTURE_REPORT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": JSON_SCHEMA_DRAFT,
    "$id": JSON_SCHEMA_ID,
    "title": "cloud-posture-watch posture report",
    "type": "object",
    "additionalProperties": True,
    "required": [
        "$schema",
        "schema_version",
        "run_id",
        "provider",
        "assessed_at",
        "baseline_name",
        "total_resources",
        "risk_score",
        "risk_level",
        "risk_model",
        "finding_counts",
        "findings",
        "drift_items",
    ],
    "properties": {
        "$schema": {"const": JSON_SCHEMA_ID},
        "schema_version": {"const": SCHEMA_VERSION},
        "run_id": {"type": "string", "minLength": 1},
        "provider": {"enum": list(PROVIDERS)},
        "assessed_at": {
            "type": "string",
            "description": "UTC timestamp in ISO-8601 form with a trailing Z.",
        },
        "baseline_name": {"type": ["string", "null"]},
        "total_resources": {"type": "integer", "minimum": 0},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "risk_level": {"enum": ["clear", "low", "moderate", "high"]},
        "risk_model": {
            "type": "object",
            "additionalProperties": False,
            "required": ["max_score", "severity_weights"],
            "properties": {
                "max_score": {"const": 100},
                "severity_weights": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": list(SEVERITIES),
                    "properties": {
                        "critical": {"type": "integer", "minimum": 0},
                        "high": {"type": "integer", "minimum": 0},
                        "medium": {"type": "integer", "minimum": 0},
                        "low": {"type": "integer", "minimum": 0},
                        "info": {"type": "integer", "minimum": 0},
                    },
                },
            },
        },
        "finding_counts": {
            "type": "object",
            "additionalProperties": False,
            "required": list(SEVERITIES),
            "properties": {
                severity: {"type": "integer", "minimum": 0}
                for severity in SEVERITIES
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": [
                    "provider",
                    "resource_type",
                    "resource_name",
                    "severity",
                    "flag",
                    "title",
                    "recommendation",
                    "baseline_name",
                    "baseline_control",
                ],
                "properties": {
                    "provider": {"enum": list(PROVIDERS)},
                    "resource_type": {"type": "string", "minLength": 1},
                    "resource_name": {"type": "string", "minLength": 1},
                    "severity": {"enum": list(SEVERITIES)},
                    "flag": {"type": "string", "minLength": 1},
                    "title": {"type": "string", "minLength": 1},
                    "recommendation": {"type": "string"},
                    "baseline_name": {"type": ["string", "null"]},
                    "baseline_control": {"type": ["string", "null"]},
                },
            },
        },
        "drift_items": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": [
                    "provider",
                    "resource_type",
                    "resource_name",
                    "baseline_name",
                    "control",
                    "expected",
                    "actual",
                    "importance",
                    "severity",
                ],
                "properties": {
                    "provider": {"enum": list(PROVIDERS)},
                    "resource_type": {"type": "string", "minLength": 1},
                    "resource_name": {"type": "string", "minLength": 1},
                    "baseline_name": {"type": "string", "minLength": 1},
                    "control": {"type": "string", "minLength": 1},
                    "expected": {},
                    "actual": {},
                    "importance": {"enum": list(IMPORTANCE_LEVELS)},
                    "severity": {"enum": list(SEVERITIES)},
                },
            },
        },
    },
}


def validate_posture_report_json_contract(document: dict[str, Any]) -> list[str]:
    """
    Return human-readable contract errors for a generated posture report JSON doc.

    This intentionally covers the stable v1 contract fields without attempting
    to implement the full JSON Schema specification.
    """
    errors: list[str] = []
    required = POSTURE_REPORT_JSON_SCHEMA["required"]
    for key in required:
        if key not in document:
            errors.append(f"missing required top-level field: {key}")

    if document.get("$schema") != JSON_SCHEMA_ID:
        errors.append("unexpected $schema value")
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append("unexpected schema_version value")
    if document.get("provider") not in PROVIDERS:
        errors.append("provider must be one of aws, azure, or gcp")
    if not isinstance(document.get("total_resources"), int) or document.get("total_resources", -1) < 0:
        errors.append("total_resources must be a non-negative integer")
    if not isinstance(document.get("risk_score"), int) or not 0 <= document.get("risk_score", -1) <= 100:
        errors.append("risk_score must be an integer from 0 to 100")
    if document.get("risk_level") not in ("clear", "low", "moderate", "high"):
        errors.append("risk_level must be clear, low, moderate, or high")

    finding_counts = document.get("finding_counts")
    if not isinstance(finding_counts, dict):
        errors.append("finding_counts must be an object")
    else:
        for severity in SEVERITIES:
            if not isinstance(finding_counts.get(severity), int):
                errors.append(f"finding_counts.{severity} must be an integer")

    risk_model = document.get("risk_model")
    if not isinstance(risk_model, dict):
        errors.append("risk_model must be an object")
    elif risk_model.get("max_score") != 100:
        errors.append("risk_model.max_score must be 100")

    if not isinstance(document.get("findings"), list):
        errors.append("findings must be an array")
    if not isinstance(document.get("drift_items"), list):
        errors.append("drift_items must be an array")

    return errors
