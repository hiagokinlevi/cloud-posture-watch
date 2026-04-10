"""
Shared risk scoring model for cloud posture findings.

The model intentionally stays simple and deterministic so CI gates, Markdown
reports, JSON exports, and HTML reports describe the same risk level.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

MAX_RISK_SCORE = 100


@dataclass(frozen=True)
class RiskBand:
    """Human-readable risk band for a numeric posture score."""

    name: str
    min_score: int
    max_score: int
    summary: str


RISK_BANDS: tuple[RiskBand, ...] = (
    RiskBand(
        name="clear",
        min_score=0,
        max_score=0,
        summary="No findings detected. The assessed resources meet the baseline requirements.",
    ),
    RiskBand(
        name="low",
        min_score=1,
        max_score=19,
        summary="Low risk. A small number of improvements are recommended.",
    ),
    RiskBand(
        name="moderate",
        min_score=20,
        max_score=49,
        summary="Moderate risk. Several controls are missing or misconfigured. Review high findings promptly.",
    ),
    RiskBand(
        name="high",
        min_score=50,
        max_score=MAX_RISK_SCORE,
        summary="High risk. Critical or numerous high-severity findings detected. Immediate remediation is advised.",
    ),
)


def normalize_severity(severity: Any) -> str:
    """Return a lower-case severity string from enums, strings, or finding objects."""
    value = getattr(severity, "severity", severity)
    value = getattr(value, "value", value)
    return str(value).lower()


def severity_weight(severity: Any) -> int:
    """Return the numeric score contribution for one finding severity."""
    return SEVERITY_WEIGHTS.get(normalize_severity(severity), 0)


def severity_rank(severity: Any) -> int:
    """Return the ordinal severity rank used for sorting and gates."""
    return SEVERITY_RANK.get(normalize_severity(severity), 0)


def calculate_risk_score(findings: Iterable[Any]) -> int:
    """Calculate the capped 0-100 posture score for a finding collection."""
    raw = sum(severity_weight(finding) for finding in findings)
    return min(raw, MAX_RISK_SCORE)


def classify_risk_score(score: int) -> RiskBand:
    """Map a numeric posture score to a stable risk band."""
    bounded = max(0, min(score, MAX_RISK_SCORE))
    for band in RISK_BANDS:
        if band.min_score <= bounded <= band.max_score:
            return band
    return RISK_BANDS[-1]
