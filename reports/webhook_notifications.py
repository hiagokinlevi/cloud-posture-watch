"""Webhook notification payloads for posture reports."""
from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from schemas.posture import PostureFinding, PostureReport


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _trim(text: str | None, limit: int = 160) -> str:
    value = " ".join((text or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _top_findings(findings: list[PostureFinding], limit: int = 5) -> list[PostureFinding]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity.value, 0),
            item.resource_name,
            item.flag,
        ),
        reverse=True,
    )[:limit]


def _summary(report: PostureReport) -> str:
    counts = report.finding_counts
    return (
        f"{report.provider.value.upper()} posture run {report.run_id}: "
        f"{len(report.findings)} finding(s) across {report.total_resources} resource(s). "
        f"CRITICAL={counts['critical']} HIGH={counts['high']} "
        f"MEDIUM={counts['medium']} LOW={counts['low']}"
    )


def build_slack_payload(report: PostureReport, dashboard_url: str | None = None) -> dict[str, Any]:
    """Build a Slack incoming-webhook payload without sending it."""
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{report.provider.value.upper()} posture findings",
            },
        },
        {"type": "section", "text": {"type": "plain_text", "text": _summary(report)}},
    ]
    for finding in _top_findings(report.findings):
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "text": (
                        f"{finding.severity.value.upper()} {finding.flag}: "
                        f"{_trim(finding.title)} [{_trim(finding.resource_name, 80)}]"
                    ),
                },
            }
        )
    if dashboard_url:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "plain_text", "text": f"Report: {dashboard_url}"},
            }
        )
    return {"text": _summary(report), "blocks": blocks}


def build_teams_payload(report: PostureReport, dashboard_url: str | None = None) -> dict[str, Any]:
    """Build a Microsoft Teams incoming-webhook MessageCard payload without sending it."""
    facts = [
        {"name": "Provider", "value": report.provider.value.upper()},
        {"name": "Run ID", "value": report.run_id},
        {"name": "Findings", "value": str(len(report.findings))},
        {"name": "Resources", "value": str(report.total_resources)},
    ]
    for finding in _top_findings(report.findings):
        facts.append(
            {
                "name": f"{finding.severity.value.upper()} {finding.flag}",
                "value": f"{_trim(finding.title)} [{_trim(finding.resource_name, 80)}]",
            }
        )

    payload: dict[str, Any] = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": _summary(report),
        "themeColor": "B00020" if report.has_high_or_critical else "2E7D32",
        "title": f"{report.provider.value.upper()} posture findings",
        "sections": [{"facts": facts, "text": _summary(report)}],
    }
    if dashboard_url:
        payload["potentialAction"] = [
            {
                "@type": "OpenUri",
                "name": "Open report",
                "targets": [{"os": "default", "uri": dashboard_url}],
            }
        ]
    return payload


def build_webhook_payload(
    report: PostureReport,
    target: str,
    dashboard_url: str | None = None,
) -> dict[str, Any]:
    """Build a Slack or Teams webhook payload from a posture report."""
    normalized_target = target.lower()
    if normalized_target == "slack":
        return build_slack_payload(report, dashboard_url=dashboard_url)
    if normalized_target == "teams":
        return build_teams_payload(report, dashboard_url=dashboard_url)
    raise ValueError(f"Unsupported webhook target: {target}")


def send_webhook_payload(
    webhook_url: str,
    payload: dict[str, Any],
    timeout_seconds: float = 10,
) -> int:
    """POST a JSON payload to a webhook URL and return the HTTP status code."""
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return int(response.status)
    except HTTPError as exc:
        raise RuntimeError(f"Webhook returned HTTP {exc.code}") from exc
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"Webhook delivery failed: {reason}") from exc
