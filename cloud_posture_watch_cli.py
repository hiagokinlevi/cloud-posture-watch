"""Repository-unique console entrypoint for cloud-posture-watch."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parent / "cli" / "main.py"
_SPEC = importlib.util.spec_from_file_location("cloud_posture_watch_local_cli", _MODULE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load CLI module from {_MODULE_PATH}")

_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
cli = _MODULE.cli
