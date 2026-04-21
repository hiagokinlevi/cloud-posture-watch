from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


_SARIF_VERSION = "2.1.0"
_SCHEMA_URI = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"


def _normalize_level(severity: str) -> str:
    sev = (severity or "").strip().lower()
    if sev in {"critical", "high"}:
        return "error"
    if sev in {"medium", "moderate"}:
        return "warning"
    if sev in {"low", "info", "informational"}:
        return "note"
    return "warning"


def _extract_message_and_rule(finding: Dict[str, Any]) -> Tuple[str, str]:
    message = (
        finding.get("description")
        or finding.get("message")
        or finding.get("title")
        or "Security posture finding"
    )
    rule_id = (
        finding.get("rule_id")
        or finding.get("ruleId")
        or finding.get("check_id")
        or finding.get("id")
        or "cloud-posture-watch/finding"
    )
    return str(message), str(rule_id)


def _extract_resource(finding: Dict[str, Any]) -> str:
    return str(
        finding.get("resource")
        or finding.get("resource_id")
        or finding.get("target")
        or finding.get("name")
        or "cloud-resource"
    )


def _collect_findings(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [f for f in payload if isinstance(f, dict)]
    if not isinstance(payload, dict):
        return []

    if isinstance(payload.get("findings"), list):
        return [f for f in payload["findings"] if isinstance(f, dict)]

    # Fallback: flatten provider/group lists that contain finding-like dicts.
    collected: List[Dict[str, Any]] = []
    for value in payload.values():
        if isinstance(value, list):
            collected.extend([f for f in value if isinstance(f, dict)])
    return collected


def findings_to_sarif(findings_payload: Any) -> Dict[str, Any]:
    findings = _collect_findings(findings_payload)

    rules_index: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        message, rule_id = _extract_message_and_rule(finding)
        resource = _extract_resource(finding)
        severity = str(finding.get("severity", "medium"))
        level = _normalize_level(severity)

        if rule_id not in rules_index:
            rules_index[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{message} (resource: {resource}, severity: {severity})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": resource}
                        }
                    }
                ],
            }
        )

    return {
        "$schema": _SCHEMA_URI,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloud-posture-watch",
                        "informationUri": "https://github.com/",
                        "rules": list(rules_index.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def export_sarif(findings_payload: Any, output_path: str) -> Path:
    sarif = findings_to_sarif(findings_payload)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path
