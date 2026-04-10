"""Diff-based watch mode for saved posture reports."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from schemas.posture import PostureFinding, PostureReport


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _finding_key(finding: PostureFinding) -> tuple[str, str, str, str, str]:
    return (
        finding.resource_type,
        finding.resource_name,
        finding.flag,
        finding.severity.value,
        finding.provider.value,
    )


def _threshold_rank(alert_on: str) -> int:
    return SEVERITY_ORDER.get(alert_on.lower(), 3)


@dataclass(frozen=True)
class WatchDelta:
    """Change summary between two posture snapshots."""

    current_run_id: str
    previous_run_id: str | None
    new_findings: list[PostureFinding]
    resolved_findings: list[PostureFinding]
    persistent_findings: list[PostureFinding]

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.resolved_findings)


def diff_posture_reports(
    current: PostureReport,
    previous: PostureReport | None,
) -> WatchDelta:
    """Return the new, resolved, and persistent findings between reports."""
    if previous and current.provider != previous.provider:
        raise ValueError(
            "Watch mode requires matching providers in the current and previous reports."
        )

    current_by_key = {_finding_key(finding): finding for finding in current.findings}
    previous_by_key = (
        {_finding_key(finding): finding for finding in previous.findings}
        if previous
        else {}
    )

    new_keys = current_by_key.keys() - previous_by_key.keys()
    resolved_keys = previous_by_key.keys() - current_by_key.keys()
    persistent_keys = current_by_key.keys() & previous_by_key.keys()

    return WatchDelta(
        current_run_id=current.run_id,
        previous_run_id=previous.run_id if previous else None,
        new_findings=sorted(
            (current_by_key[key] for key in new_keys),
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity.value, 0),
                finding.resource_name,
                finding.flag,
            ),
            reverse=True,
        ),
        resolved_findings=sorted(
            (previous_by_key[key] for key in resolved_keys),
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity.value, 0),
                finding.resource_name,
                finding.flag,
            ),
            reverse=True,
        ),
        persistent_findings=sorted(
            (current_by_key[key] for key in persistent_keys),
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity.value, 0),
                finding.resource_name,
                finding.flag,
            ),
            reverse=True,
        ),
    )


def should_alert(
    delta: WatchDelta,
    alert_on: str = "high",
    *,
    first_run: bool = False,
    alert_on_first_run: bool = False,
) -> bool:
    """Return True when watch mode should emit an alert."""
    if not delta.new_findings:
        return False
    if first_run and not alert_on_first_run:
        return False

    threshold = _threshold_rank(alert_on)
    return any(
        SEVERITY_ORDER.get(finding.severity.value, 0) >= threshold
        for finding in delta.new_findings
    )


def build_watch_notification_report(
    current: PostureReport,
    delta: WatchDelta,
) -> PostureReport:
    """Create a report that contains only newly introduced findings."""
    return PostureReport(
        run_id=current.run_id,
        provider=current.provider,
        baseline_name=current.baseline_name,
        assessed_at=current.assessed_at,
        total_resources=current.total_resources,
        findings=list(delta.new_findings),
        drift_items=[],
    )


def write_watch_state(input_path: Path, state_path: Path) -> None:
    """Persist the current JSON report so the next run can diff against it."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(input_path.read_text(encoding="utf-8"), encoding="utf-8")
