from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _resolve_baseline_version(baseline_path: str | None, baseline_data: dict[str, Any] | None = None) -> str | None:
    """Return a stable version identifier for a resolved baseline.

    Preference order:
    1) SHA256 hash of baseline file bytes (when a path is available and readable)
    2) SHA256 hash of serialized baseline object (fallback)
    """
    if baseline_path:
        try:
            raw = Path(baseline_path).read_bytes()
            return f"sha256:{hashlib.sha256(raw).hexdigest()}"
        except OSError:
            pass

    if baseline_data is not None:
        try:
            payload = json.dumps(baseline_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            return f"sha256:{hashlib.sha256(payload).hexdigest()}"
        except Exception:
            return None

    return None


def build_report_metadata(existing_metadata: dict[str, Any] | None, baseline_name: str | None, baseline_path: str | None, baseline_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Attach baseline provenance metadata to report metadata."""
    metadata = dict(existing_metadata or {})

    if baseline_name:
        metadata["baseline_name"] = baseline_name

    baseline_version = _resolve_baseline_version(baseline_path, baseline_data)
    if baseline_version:
        metadata["baseline_version"] = baseline_version

    return metadata


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render markdown report with metadata section including baseline provenance."""
    lines: list[str] = ["# Cloud Posture Watch Report", ""]

    metadata = report.get("metadata") or {}
    if metadata:
        lines.extend(["## Metadata", ""])
        for key in ["generated_at", "provider", "baseline_name", "baseline_version"]:
            if key in metadata:
                lines.append(f"- **{key}**: `{metadata[key]}`")
        lines.append("")

    findings = report.get("findings", [])
    lines.extend(["## Findings", ""])
    if not findings:
        lines.append("No findings.")
    else:
        for f in findings:
            title = f.get("title", "Untitled")
            severity = f.get("severity", "unknown")
            lines.append(f"- **[{severity}]** {title}")

    lines.append("")
    return "\n".join(lines)
