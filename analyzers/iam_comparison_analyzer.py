"""
Cross-cloud IAM comparison report builder.

This module combines the existing offline AWS IAM, Azure RBAC, and GCP IAM
analyzer outputs into one review artifact. It does not introduce new live cloud
collection; callers pass already-analyzed provider reports.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_CATEGORY_BY_CHECK_ID = {
    "AWS-IAM-001": "credential_hygiene",
    "AWS-IAM-002": "credential_hygiene",
    "AWS-IAM-003": "credential_hygiene",
    "AWS-IAM-004": "custom_or_wildcard_permissions",
    "AWS-IAM-005": "custom_or_wildcard_permissions",
    "AWS-IAM-006": "privileged_standing_access",
    "AZ-RBAC-001": "privileged_standing_access",
    "AZ-RBAC-002": "privileged_standing_access",
    "AZ-RBAC-003": "external_or_public_access",
    "AZ-RBAC-004": "privileged_standing_access",
    "AZ-RBAC-005": "custom_or_wildcard_permissions",
    "AZ-RBAC-006": "privileged_standing_access",
    "GCP-IAM-001": "privileged_standing_access",
    "GCP-IAM-002": "external_or_public_access",
    "GCP-IAM-003": "privileged_standing_access",
    "GCP-IAM-004": "external_or_public_access",
    "GCP-IAM-005": "credential_hygiene",
    "GCP-IAM-006": "credential_hygiene",
    "GCP-IAM-007": "custom_or_wildcard_permissions",
}

_CATEGORY_LABELS = {
    "credential_hygiene": "Credential hygiene",
    "privileged_standing_access": "Privileged standing access",
    "external_or_public_access": "External or public access",
    "custom_or_wildcard_permissions": "Custom or wildcard permissions",
}


@dataclass
class IAMComparisonFinding:
    """Normalized IAM finding across AWS, Azure, and GCP analyzers."""

    provider: str
    check_id: str
    severity: str
    category: str
    resource: str
    title: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "check_id": self.check_id,
            "severity": self.severity,
            "category": self.category,
            "resource": self.resource,
            "title": self.title,
            "recommendation": self.recommendation,
        }


@dataclass
class IAMProviderSummary:
    """Per-provider IAM comparison summary."""

    provider: str
    resources_analyzed: int = 0
    risk_score: int = 0
    finding_counts: dict[str, int] = field(default_factory=dict)
    triggered_controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "resources_analyzed": self.resources_analyzed,
            "risk_score": self.risk_score,
            "finding_counts": self.finding_counts,
            "triggered_controls": self.triggered_controls,
        }


@dataclass
class IAMComparisonReport:
    """Cross-cloud IAM comparison report."""

    providers: list[IAMProviderSummary] = field(default_factory=list)
    findings: list[IAMComparisonFinding] = field(default_factory=list)
    category_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def cross_cloud_risk_score(self) -> int:
        if not self.providers:
            return 0
        return max(provider.risk_score for provider in self.providers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "cross_cloud_risk_score": self.cross_cloud_risk_score,
            "generated_at": self.generated_at,
            "providers": [provider.to_dict() for provider in self.providers],
            "category_counts": self.category_counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def build_iam_comparison_report(
    *,
    aws_report: Any | None = None,
    azure_report: Any | None = None,
    gcp_report: Any | None = None,
) -> IAMComparisonReport:
    """Build a normalized cross-cloud IAM report from provider analyzer reports."""
    provider_reports = [
        ("aws", aws_report),
        ("azure", azure_report),
        ("gcp", gcp_report),
    ]
    summaries: list[IAMProviderSummary] = []
    findings: list[IAMComparisonFinding] = []

    for provider, report in provider_reports:
        if report is None:
            continue
        provider_findings = _normalize_provider_findings(provider, report)
        summaries.append(
            IAMProviderSummary(
                provider=provider,
                resources_analyzed=_resources_analyzed(provider, report),
                risk_score=int(getattr(report, "risk_score", 0) or 0),
                finding_counts=_severity_counts(provider_findings),
                triggered_controls=sorted({finding.check_id for finding in provider_findings}),
            )
        )
        findings.extend(provider_findings)

    return IAMComparisonReport(
        providers=summaries,
        findings=sorted(
            findings,
            key=lambda finding: (
                -_SEVERITY_ORDER.get(finding.severity, 0),
                finding.provider,
                finding.check_id,
                finding.resource,
            ),
        ),
        category_counts=_category_counts(findings),
    )


def generate_iam_comparison_markdown(report: IAMComparisonReport) -> str:
    """Render a cross-cloud IAM comparison report as Markdown."""
    lines = [
        "# Cross-Cloud IAM Comparison Report",
        "",
        f"**Risk score:** {report.cross_cloud_risk_score}/100  ",
        f"**Total findings:** {report.total_findings}  ",
        "",
        "## Provider Summary",
        "",
        "| Provider | Resources | Risk Score | Critical | High | Medium | Low | Controls |",
        "|----------|-----------|------------|----------|------|--------|-----|----------|",
    ]
    for provider in report.providers:
        counts = provider.finding_counts
        controls = ", ".join(provider.triggered_controls) or "None"
        lines.append(
            f"| {provider.provider.upper()} | {provider.resources_analyzed} | "
            f"{provider.risk_score} | {counts.get('critical', 0)} | "
            f"{counts.get('high', 0)} | {counts.get('medium', 0)} | "
            f"{counts.get('low', 0)} | {controls} |"
        )

    lines += [
        "",
        "## Comparison Themes",
        "",
        "| Theme | AWS | Azure | GCP |",
        "|-------|-----|-------|-----|",
    ]
    for category, label in _CATEGORY_LABELS.items():
        counts = report.category_counts.get(category, {})
        lines.append(
            f"| {label} | {counts.get('aws', 0)} | {counts.get('azure', 0)} | "
            f"{counts.get('gcp', 0)} |"
        )

    lines += ["", "## Prioritized Findings", ""]
    if not report.findings:
        lines.append("No IAM findings were identified in the supplied evidence.")
    else:
        for index, finding in enumerate(report.findings, start=1):
            lines += [
                f"### {index}. [{finding.severity.upper()}] {finding.title}",
                "",
                f"- **Provider:** {finding.provider.upper()}",
                f"- **Check:** `{finding.check_id}`",
                f"- **Theme:** {_CATEGORY_LABELS.get(finding.category, finding.category)}",
                f"- **Resource:** `{finding.resource}`",
                f"- **Recommendation:** {finding.recommendation}",
                "",
            ]

    return "\n".join(lines).rstrip() + "\n"


def save_iam_comparison_report(
    report: IAMComparisonReport,
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """Write Markdown and JSON IAM comparison reports."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime(report.generated_at))
    markdown_path = output_path / f"iam_comparison_{timestamp}.md"
    json_path = output_path / f"iam_comparison_{timestamp}.json"
    markdown_path.write_text(generate_iam_comparison_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return markdown_path, json_path


def _normalize_provider_findings(provider: str, report: Any) -> list[IAMComparisonFinding]:
    return [_normalize_finding(provider, finding) for finding in getattr(report, "findings", [])]


def _normalize_finding(provider: str, finding: Any) -> IAMComparisonFinding:
    check_id = str(getattr(finding, "check_id", getattr(finding, "rule_id", "unknown")))
    severity = str(getattr(getattr(finding, "severity", ""), "value", getattr(finding, "severity", ""))).lower()
    recommendation = str(
        getattr(finding, "recommendation", "")
        or getattr(finding, "remediation", "")
        or getattr(finding, "detail", "")
    )
    return IAMComparisonFinding(
        provider=provider,
        check_id=check_id,
        severity=severity,
        category=_CATEGORY_BY_CHECK_ID.get(check_id, "provider_specific"),
        resource=_finding_resource(provider, finding),
        title=str(getattr(finding, "title", check_id)),
        recommendation=recommendation,
    )


def _finding_resource(provider: str, finding: Any) -> str:
    if provider == "azure":
        scope = str(getattr(finding, "scope", "unknown"))
        principal = str(getattr(finding, "principal", "unknown"))
        role = str(getattr(finding, "role", "unknown"))
        return f"{scope}:{principal}:{role}"
    if provider == "gcp":
        resource = str(getattr(finding, "resource", "unknown"))
        role = str(getattr(finding, "role", ""))
        member = str(getattr(finding, "member", ""))
        return ":".join(part for part in [resource, role, member] if part)
    return str(getattr(finding, "resource", getattr(finding, "resource_name", "unknown")))


def _resources_analyzed(provider: str, report: Any) -> int:
    if provider == "aws":
        return int(getattr(report, "snapshots_analyzed", 0) or 0)
    if provider == "azure":
        return int(getattr(report, "assignments_analyzed", 0) or 0)
    if provider == "gcp":
        return int(getattr(report, "policies_analyzed", 0) or 0)
    return 0


def _severity_counts(findings: list[IAMComparisonFinding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _category_counts(findings: list[IAMComparisonFinding]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {
        category: {"aws": 0, "azure": 0, "gcp": 0}
        for category in _CATEGORY_LABELS
    }
    for finding in findings:
        counts.setdefault(finding.category, {"aws": 0, "azure": 0, "gcp": 0})
        counts[finding.category][finding.provider] = (
            counts[finding.category].get(finding.provider, 0) + 1
        )
    return counts
