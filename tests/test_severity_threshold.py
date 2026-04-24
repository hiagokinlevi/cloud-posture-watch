from cloud_posture_watch_cli import filter_findings_by_severity_threshold


def test_severity_threshold_filters_lower_severity_findings():
    findings = [
        {"id": "f-1", "severity": "low"},
        {"id": "f-2", "severity": "medium"},
        {"id": "f-3", "severity": "high"},
    ]

    filtered = filter_findings_by_severity_threshold(findings, "medium")

    assert [f["id"] for f in filtered] == ["f-2", "f-3"]
