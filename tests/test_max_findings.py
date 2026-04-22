from cloud_posture_watch_cli import apply_max_findings_cap, assemble_report


def test_max_findings_truncates_lowest_priority_first():
    findings = [
        {"title": "low", "severity": "low", "risk_score": 1},
        {"title": "critical", "severity": "critical", "risk_score": 10},
        {"title": "medium", "severity": "medium", "risk_score": 5},
    ]

    kept, meta = apply_max_findings_cap(findings, 2)
    titles = {f["title"] for f in kept}

    assert "critical" in titles
    assert "medium" in titles
    assert "low" not in titles
    assert meta["truncated"] is True
    assert meta["original_count"] == 3
    assert meta["emitted_count"] == 2


def test_no_truncation_when_under_cap():
    findings = [{"title": "only", "severity": "high", "risk_score": 8}]
    report = assemble_report(findings, 5)

    assert report["count"] == 1
    assert "truncated" not in report
    assert report["findings"][0]["title"] == "only"
