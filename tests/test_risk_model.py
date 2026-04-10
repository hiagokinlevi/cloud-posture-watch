from __future__ import annotations

from schemas.posture import PostureFinding, Provider, Severity
from schemas.risk import (
    SEVERITY_WEIGHTS,
    calculate_risk_score,
    classify_risk_score,
    severity_rank,
    severity_weight,
)


def _finding(severity: Severity) -> PostureFinding:
    return PostureFinding(
        provider=Provider.AWS,
        resource_type="s3_bucket",
        resource_name="bucket-a",
        severity=severity,
        flag="TEST",
        title="Test finding",
        recommendation="Fix it.",
    )


def test_severity_weight_accepts_enum_string_and_finding():
    finding = _finding(Severity.CRITICAL)

    assert severity_weight(Severity.CRITICAL) == SEVERITY_WEIGHTS["critical"]
    assert severity_weight("high") == SEVERITY_WEIGHTS["high"]
    assert severity_weight(finding) == SEVERITY_WEIGHTS["critical"]


def test_calculate_risk_score_uses_capped_weighted_sum():
    findings = [_finding(Severity.CRITICAL)] * 20

    assert calculate_risk_score(findings) == 100


def test_calculate_risk_score_combines_multiple_severities():
    findings = [
        _finding(Severity.CRITICAL),
        _finding(Severity.HIGH),
        _finding(Severity.MEDIUM),
        _finding(Severity.LOW),
        _finding(Severity.INFO),
    ]

    assert calculate_risk_score(findings) == 18


def test_classify_risk_score_returns_stable_bands():
    assert classify_risk_score(0).name == "clear"
    assert classify_risk_score(1).name == "low"
    assert classify_risk_score(20).name == "moderate"
    assert classify_risk_score(50).name == "high"
    assert classify_risk_score(999).name == "high"


def test_severity_rank_orders_gate_thresholds():
    assert severity_rank("critical") > severity_rank("high")
    assert severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low")
