from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


def _ensure_output_dir_writable(output_dir: Path) -> None:
    """Create output directory if needed and validate writability.

    Exits with code 2 and actionable error messaging when setup fails.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(
            f"ERROR: Unable to create output directory '{output_dir}': {exc}. "
            "Provide a writable path with --output-dir.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    # Preflight write test to catch permission/runtime issues before report generation.
    try:
        with tempfile.NamedTemporaryFile(prefix=".cpw_write_test_", dir=output_dir, delete=True) as _:
            pass
    except OSError as exc:
        print(
            f"ERROR: Output directory '{output_dir}' is not writable: {exc}. "
            "Adjust permissions or choose a different --output-dir.",
            file=sys.stderr,
        )
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--output-dir", default="reports", help="Directory to write generated reports")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    _ensure_output_dir_writable(output_dir)

    result: dict[str, Any] = {
        "status": "ok",
        "output_dir": str(output_dir),
    }

    if args.json:
        print(json.dumps(result))
    else:
        print(f"cloud-posture-watch ready. output_dir={output_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
