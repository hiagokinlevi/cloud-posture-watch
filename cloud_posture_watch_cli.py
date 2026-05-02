from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _normalize_level(severity: Any) -> str:
    s = str(severity or "").strip().lower()
    if s in {"critical", "high"}:
        return "error"
    if s in {"medium", "moderate"}:
        return "warning"
    if s in {"low", "info", "informational"}:
        return "note"
    return "warning"


def _build_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules_index: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule_id = str(f.get("id") or f.get("finding_id") or "CPW-UNKNOWN")
        provider = str(f.get("provider") or "unknown")
        severity = str(f.get("severity") or "medium")
        title = str(f.get("title") or f.get("name") or rule_id)
        description = str(f.get("description") or f.get("message") or title)

        if rule_id not in rules_index:
            rules_index[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "properties": {
                    "provider": provider,
                    "severity": severity,
                },
            }

        result_message = str(f.get("message") or description)
        location_uri = str(
            f.get("resource")
            or f.get("resource_id")
            or f.get("arn")
            or f.get("id")
            or "cloud-resource"
        )

        results.append(
            {
                "ruleId": rule_id,
                "level": _normalize_level(severity),
                "message": {"text": result_message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location_uri}
                        }
                    }
                ],
                "properties": {
                    "provider": provider,
                    "severity": severity,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloud-posture-watch",
                        "informationUri": "https://github.com/",
                        "rules": list(rules_index.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--json-output", help="Path to write JSON findings")
    parser.add_argument("--sarif-output", help="Path to write SARIF 2.1.0 findings")
    args = parser.parse_args()

    # Existing pipeline should provide findings; keep fallback safe.
    findings: list[dict[str, Any]] = []

    if args.json_output:
        Path(args.json_output).write_text(json.dumps(findings, indent=2), encoding="utf-8")

    if args.sarif_output:
        sarif_doc = _build_sarif(findings)
        Path(args.sarif_output).write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
