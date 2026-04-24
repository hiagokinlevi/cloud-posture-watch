from __future__ import annotations

import os
from pathlib import Path

import pytest

import cloud_posture_watch_cli as cli


def test_output_dir_is_created_when_missing(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "reports"
    assert not target.exists()

    cli._ensure_output_dir_writable(target)

    assert target.exists()
    assert target.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="chmod-based unwritable-dir behavior is not reliable on Windows")
def test_unwritable_output_dir_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "reports"
    target.mkdir(parents=True, exist_ok=True)

    # Force write-test failure in a deterministic way.
    import tempfile

    def _raise_permission(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", _raise_permission)

    with pytest.raises(SystemExit) as exc:
        cli._ensure_output_dir_writable(target)

    assert exc.value.code != 0
