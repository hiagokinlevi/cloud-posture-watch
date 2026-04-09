"""
Logging Coverage Analyzer
==========================
Checks whether audit trails, resource access logs, and network flow logs are
enabled across cloud resources.

Logging is a foundational security control: without it, incident response,
forensics, and compliance reporting are severely hindered.

The analyzer works with any posture object that exposes a `logging_enabled`
boolean (or equivalent attribute name, configurable per provider).

Coverage levels
---------------
- full     : All relevant logging is enabled and directed to a durable destination
- partial  : Some logging is enabled but gaps exist
- none     : No logging detected; high-priority remediation required
"""
from dataclasses import dataclass
from typing import Any


@dataclass
class LoggingGap:
    """A single logging coverage gap finding."""
    provider: str
    resource_type: str
    resource_name: str
    coverage_level: str   # "full", "partial", "none"
    missing_controls: list[str]
    recommendation: str


# Per-provider logging control definitions
# Each value is a dict mapping attribute name -> human-readable control name
_PROVIDER_LOGGING_CONTROLS: dict[str, dict[str, str]] = {
    "aws": {
        "logging_enabled": "S3 server access logging",
        # Additional controls would be added here as more collectors are implemented
    },
    "azure": {
        # Azure storage does not expose logging_enabled in the mgmt SDK directly;
        # gaps are surfaced via diagnostic settings (future collector).
        # Placeholder entry so the framework processes Azure postures.
        "logging_enabled": "Storage Analytics logging",
    },
    "gcp": {
        "logging_enabled": "GCS access logging",
    },
}


def analyze_logging_coverage(
    postures: list[Any],
    provider: str,
    resource_type: str = "storage",
) -> list[LoggingGap]:
    """
    Analyze a list of resource posture objects for logging coverage gaps.

    Args:
        postures: List of posture dataclass instances. Each must have a `name`
                  attribute. Logging-related attributes are looked up per provider.
        provider: Cloud provider identifier ("aws", "azure", "gcp").
        resource_type: Descriptive resource type string for findings.

    Returns:
        List of LoggingGap findings, sorted by coverage level severity.
    """
    gaps: list[LoggingGap] = []
    coverage_order = {"none": 0, "partial": 1, "full": 2}

    # Determine which attributes to check for this provider
    controls = _PROVIDER_LOGGING_CONTROLS.get(provider, {})

    for posture in postures:
        resource_name = getattr(posture, "name", "unknown")
        missing: list[str] = []

        for attr, control_name in controls.items():
            value = getattr(posture, attr, None)
            if value is False:
                missing.append(control_name)

        if not missing:
            # All checked controls are enabled — full coverage for these attributes
            continue

        # Classify coverage level
        if len(missing) == len(controls):
            coverage_level = "none"
            recommendation = (
                f"Enable all logging controls for this {resource_type}. "
                f"Missing: {', '.join(missing)}."
            )
        else:
            coverage_level = "partial"
            recommendation = (
                f"Some logging controls are missing for this {resource_type}. "
                f"Enable: {', '.join(missing)}."
            )

        gaps.append(LoggingGap(
            provider=provider,
            resource_type=resource_type,
            resource_name=resource_name,
            coverage_level=coverage_level,
            missing_controls=missing,
            recommendation=recommendation,
        ))

    # Sort so "none" (most severe) appears first
    gaps.sort(key=lambda g: coverage_order.get(g.coverage_level, 99))
    return gaps


def summarize_logging_coverage(gaps: list[LoggingGap]) -> dict[str, int]:
    """
    Return a count of resources by coverage level for use in report summaries.

    Args:
        gaps: List of LoggingGap findings.

    Returns:
        Dict with keys "full", "partial", "none" and counts.
    """
    summary: dict[str, int] = {"full": 0, "partial": 0, "none": 0}
    for gap in gaps:
        level = gap.coverage_level
        if level in summary:
            summary[level] += 1
    return summary
