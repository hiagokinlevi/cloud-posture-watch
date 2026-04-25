import json
import subprocess
import sys
from pathlib import Path


def test_cli_json_stdout_emits_valid_json_and_exits_success(tmp_path: Path) -> None:
    output_file = tmp_path / "out.json"

    proc = subprocess.run(
        [
            sys.executable,
            "cloud_posture_watch_cli.py",
            "--provider",
            "all",
            "--output",
            str(output_file),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    assert proc.stderr == ""

    payload = json.loads(proc.stdout)
    assert isinstance(payload, dict)
    assert payload.get("project") == "cloud-posture-watch"
    assert payload.get("provider") == "all"
    assert "findings" in payload

    assert output_file.exists()
