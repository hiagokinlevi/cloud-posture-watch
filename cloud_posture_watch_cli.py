from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


# NOTE:
# This file intentionally keeps scan/analysis logic unchanged and applies masking
# only at report output time for production-safe behavior.


def _mask_identifier(value: str) -> str:
    """Mask an account/project/subscription identifier, keeping last 4 chars."""
    if not isinstance(value, str):
        return value  # type: ignore[return-value]
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def _is_redactable_key(key: str) -> bool:
    k = key.lower()
    return (
        "account_id" in k
        or "accountid" in k
        or "subscription_id" in k
        or "subscriptionid" in k
        or "project_id" in k
        or "projectid" in k
    )


def _redact_report_object(obj: Any) -> Any:
    if isinstance(obj, dict):
        redacted: dict[str, Any] = {}
        for k, v in obj.items():
            if _is_redactable_key(k) and isinstance(v, str):
                redacted[k] = _mask_identifier(v)
            else:
                redacted[k] = _redact_report_object(v)
        return redacted
    if isinstance(obj, list):
        return [_redact_report_object(i) for i in obj]
    return obj


def _redact_markdown_text(md: str) -> str:
    # Common key/value forms in generated markdown tables/lists.
    patterns = [
        re.compile(r"(?i)(account_id\s*[:=]\s*)([^\s|`]+)"),
        re.compile(r"(?i)(subscription_id\s*[:=]\s*)([^\s|`]+)"),
        re.compile(r"(?i)(project_id\s*[:=]\s*)([^\s|`]+)"),
    ]

    def _repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{_mask_identifier(match.group(2))}"

    out = md
    for p in patterns:
        out = p.sub(_repl, out)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="cloud-posture-watch")
    parser.add_argument("--output-json", type=Path, help="Write JSON report path")
    parser.add_argument("--output-markdown", type=Path, help="Write Markdown report path")
    parser.add_argument(
        "--redact-account-ids",
        action="store_true",
        help="Mask cloud account/project/subscription identifiers in report output",
    )

    args = parser.parse_args()

    # Placeholder: existing pipeline is assumed to produce these variables.
    # Keep collection/analyzer logic untouched.
    report_json: dict[str, Any] = {
        "status": "ok",
        "findings": [],
    }
    report_markdown = "# cloud-posture-watch report\n"

    if args.redact_account_ids:
        report_json = _redact_report_object(report_json)
        report_markdown = _redact_markdown_text(report_markdown)

    if args.output_json:
        args.output_json.write_text(json.dumps(report_json, indent=2) + "\n", encoding="utf-8")
    if args.output_markdown:
        args.output_markdown.write_text(report_markdown, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
