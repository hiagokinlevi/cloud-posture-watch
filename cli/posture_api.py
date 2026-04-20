from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query


app = FastAPI(title="cloud-posture-watch API", version="0.1.0")


def _default_reports_dir() -> Path:
    return Path("reports")


def _load_json(path: Path) -> Any:
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Report file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid JSON in report file: {path}") from exc


def _get_report_data(reports_dir: Path | None = None) -> dict[str, Any]:
    base = reports_dir or _default_reports_dir()
    report_path = base / "posture_report.json"
    data = _load_json(report_path)
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="Invalid report structure")
    return data


def _paginate(items: list[dict[str, Any]], limit: int, offset: int) -> dict[str, Any]:
    total = len(items)
    paged = items[offset : offset + limit]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": paged,
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/assets")
def list_assets(
    provider: str | None = Query(default=None),
    service: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    data = _get_report_data()
    assets = data.get("assets", [])
    if not isinstance(assets, list):
        raise HTTPException(status_code=500, detail="Invalid assets structure")

    filtered: list[dict[str, Any]] = []
    for item in assets:
        if not isinstance(item, dict):
            continue
        if provider and str(item.get("provider", "")).lower() != provider.lower():
            continue
        if service and str(item.get("service", "")).lower() != service.lower():
            continue
        filtered.append(item)

    return _paginate(filtered, limit=limit, offset=offset)


@app.get("/api/v1/findings")
def list_findings(
    provider: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    analyzer: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    data = _get_report_data()
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        raise HTTPException(status_code=500, detail="Invalid findings structure")

    filtered: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        if provider and str(item.get("provider", "")).lower() != provider.lower():
            continue
        if severity and str(item.get("severity", "")).lower() != severity.lower():
            continue
        if analyzer and str(item.get("analyzer", "")).lower() != analyzer.lower():
            continue
        filtered.append(item)

    return _paginate(filtered, limit=limit, offset=offset)


@app.get("/api/v1/risk-summary")
def risk_summary() -> dict[str, Any]:
    data = _get_report_data()
    summary = data.get("risk_summary")
    if summary is None:
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            raise HTTPException(status_code=500, detail="Invalid findings structure")
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in findings:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1
        return {"severity_counts": counts, "total_findings": len(findings)}

    if not isinstance(summary, dict):
        raise HTTPException(status_code=500, detail="Invalid risk_summary structure")
    return summary
