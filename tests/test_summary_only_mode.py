import json

from cloud_posture_watch_cli import render_markdown, serialize_json


def _sample_report():
    return {
        "findings": [
            {
                "id": "AWS-1",
                "provider": "aws",
                "severity": "high",
                "title": "Public S3 bucket",
            },
            {
                "id": "AZ-1",
                "provider": "azure",
                "severity": "medium",
                "title": "NSG open to world",
            },
        ]
    }


def test_summary_only_suppresses_detailed_sections_markdown_and_json():
    report = _sample_report()

    md = render_markdown(report, summary_only=True)
    assert "## Summary" in md
    assert "Total findings: 2" in md
    assert "## Detailed findings" not in md
    assert "AWS-1" not in md

    js = serialize_json(report, summary_only=True)
    payload = json.loads(js)
    assert "summary" in payload
    assert payload["summary"]["totals"]["findings"] == 2
    assert payload["summary"]["by_provider"]["aws"] == 1
    assert payload["summary"]["by_provider"]["azure"] == 1
    assert "findings" not in payload
