import json
import subprocess
import sys
from pathlib import Path


def _run_cli(tmp_path: Path, baseline: str = "standard"):
    md_out = tmp_path / "report.md"
    json_out = tmp_path / "report.json"

    cmd = [
        sys.executable,
        "cloud_posture_watch_cli.py",
        "scan",
        "--provider",
        "aws",
        "--baseline",
        baseline,
        "--offline",
        "--input",
        str(tmp_path / "empty-input.json"),
        "--output-markdown",
        str(md_out),
        "--output-json",
        str(json_out),
    ]

    # Provide a minimal empty offline input so scanners produce no findings.
    (tmp_path / "empty-input.json").write_text("{}", encoding="utf-8")

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result, md_out, json_out


def test_zero_findings_emits_explicit_success_blocks(tmp_path: Path):
    result, md_out, json_out = _run_cli(tmp_path)
    assert result.returncode == 0, result.stderr

    assert md_out.exists(), "Markdown output was not generated"
    assert json_out.exists(), "JSON output was not generated"

    md = md_out.read_text(encoding="utf-8")
    data = json.loads(json_out.read_text(encoding="utf-8"))

    # Markdown should contain an explicit clean success summary, not near-empty output.
    lowered = md.lower()
    assert "status: clean" in lowered or "**status:** clean" in lowered
    assert "scanned" in lowered and "resource" in lowered
    assert "baseline" in lowered

    # JSON should carry machine-readable clean status plus context.
    assert isinstance(data, dict)
    assert data.get("status") == "clean"
    assert "scanned_resources" in data
    assert isinstance(data.get("scanned_resources"), int)
    assert "baseline" in data
    assert data.get("baseline")
