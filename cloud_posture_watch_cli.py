import argparse
import json
import re
from pathlib import Path


def _looks_sensitive_key(key: str) -> bool:
    k = str(key).lower()
    return any(token in k for token in [
        "secret",
        "password",
        "token",
        "apikey",
        "api_key",
        "access_key",
        "private_key",
        "connection_string",
        "conn_string",
        "credential",
    ])


def _looks_sensitive_value(value: str) -> bool:
    if not isinstance(value, str):
        return False

    v = value.strip()

    # AWS access key id
    if re.search(r"\bAKIA[0-9A-Z]{16}\b", v):
        return True

    # Common connection string / credential-like shapes
    lowered = v.lower()
    if ("server=" in lowered or "host=" in lowered) and ("password=" in lowered or "pwd=" in lowered):
        return True
    if "accountkey=" in lowered or "sharedaccesskey=" in lowered:
        return True

    # Generic secret-like assignment pattern
    if re.search(r"(secret|token|password|passwd|pwd)\s*[:=]\s*\S+", lowered):
        return True

    return False


def redact_sensitive_literals(payload):
    """Recursively mask sensitive values while preserving structure/metadata."""
    if isinstance(payload, dict):
        redacted = {}
        for k, v in payload.items():
            if _looks_sensitive_key(k) and isinstance(v, (str, int, float, bool)):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_literals(v)
        return redacted

    if isinstance(payload, list):
        return [redact_sensitive_literals(item) for item in payload]

    if isinstance(payload, str) and _looks_sensitive_value(payload):
        return "[REDACTED]"

    return payload


def _to_markdown(report_obj: dict) -> str:
    lines = ["# cloud-posture-watch report", ""]
    findings = report_obj.get("findings", []) if isinstance(report_obj, dict) else []
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("## Findings")
    for idx, f in enumerate(findings, start=1):
        rule = f.get("rule_id", "unknown-rule")
        sev = f.get("severity", "unknown")
        msg = f.get("message", "")
        lines.append(f"{idx}. **{rule}** ({sev}) - {msg}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="cloud-posture-watch CLI")
    parser.add_argument("--output-json", default="report.json", help="Path to JSON report output")
    parser.add_argument("--output-md", default="report.md", help="Path to Markdown report output")
    parser.add_argument(
        "--redact-secrets",
        action="store_true",
        help="Mask sensitive literal values in generated JSON/Markdown reports",
    )

    args = parser.parse_args()

    # Placeholder example report object; in the real pipeline this is the analyzer output.
    report = {
        "metadata": {"tool": "cloud-posture-watch", "version": "0.1"},
        "findings": [
            {
                "rule_id": "aws.iam.access_key.exposed",
                "severity": "high",
                "message": "Potential access key literal found",
                "evidence": {
                    "value": "AKIA1234567890ABCDEF",
                    "context": "sample",
                },
            }
        ],
    }

    if args.redact_secrets:
        report = redact_sensitive_literals(report)

    json_path = Path(args.output_json)
    md_path = Path(args.output_md)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_to_markdown(report), encoding="utf-8")


if __name__ == "__main__":
    main()
