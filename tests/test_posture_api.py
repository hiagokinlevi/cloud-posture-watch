import json
from pathlib import Path

from fastapi.testclient import TestClient

from cli import posture_api


def _write_report(tmp_path: Path) -> None:
    report = {
        "assets": [
            {"id": "a1", "provider": "aws", "service": "s3"},
            {"id": "a2", "provider": "azure", "service": "storage"},
        ],
        "findings": [
            {"id": "f1", "provider": "aws", "severity": "high", "analyzer": "exposure"},
            {"id": "f2", "provider": "aws", "severity": "low", "analyzer": "logging"},
            {"id": "f3", "provider": "gcp", "severity": "critical", "analyzer": "drift"},
        ],
        "risk_summary": {"score": 72, "grade": "C"},
    }
    (tmp_path / "posture_report.json").write_text(json.dumps(report), encoding="utf-8")


def test_assets_and_findings_endpoints(tmp_path, monkeypatch):
    _write_report(tmp_path)
    monkeypatch.setattr(posture_api, "_default_reports_dir", lambda: tmp_path)

    client = TestClient(posture_api.app)

    assets = client.get("/api/v1/assets", params={"provider": "aws"})
    assert assets.status_code == 200
    body = assets.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == "a1"

    findings = client.get("/api/v1/findings", params={"provider": "aws", "severity": "high"})
    assert findings.status_code == 200
    fbody = findings.json()
    assert fbody["total"] == 1
    assert fbody["items"][0]["id"] == "f1"


def test_risk_summary_endpoint(tmp_path, monkeypatch):
    _write_report(tmp_path)
    monkeypatch.setattr(posture_api, "_default_reports_dir", lambda: tmp_path)

    client = TestClient(posture_api.app)
    resp = client.get("/api/v1/risk-summary")
    assert resp.status_code == 200
    assert resp.json() == {"score": 72, "grade": "C"}
