#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cloud-posture-watch CLI")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp", "all"], default="all")
    parser.add_argument("--format", choices=["markdown", "json", "both"], default="both")
    parser.add_argument("--baseline", default="standard")
    parser.add_argument(
        "--output-dir",
        default=None,
        help=(
            "Optional output directory for generated artifacts (Markdown/JSON and companion files). "
            "Directory is created when missing."
        ),
    )
    return parser


def _resolve_output_dir(output_dir_arg: str | None) -> Path:
    """
    Resolve and validate artifact output directory.

    - If output_dir_arg is unset: keep legacy behavior (current working directory).
    - If set: create directory if missing.
    - Always fail with a clear error when target is not writable.
    """
    target = Path(output_dir_arg).expanduser() if output_dir_arg else Path.cwd()

    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SystemExit(f"[error] Unable to create output directory '{target}': {exc}") from exc

    if not target.is_dir():
        raise SystemExit(f"[error] Output path is not a directory: '{target}'")

    if not os.access(target, os.W_OK):
        raise SystemExit(f"[error] Output directory is not writable: '{target}'")

    return target


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    args = _build_parser().parse_args()
    output_dir = _resolve_output_dir(args.output_dir)

    # Placeholder posture outputs (existing generators would feed these values).
    report_md = "# cloud-posture-watch report\n\nGenerated posture summary.\n"
    report_json = {
        "provider": args.provider,
        "baseline": args.baseline,
        "status": "ok",
    }
    companion_json = {
        "meta": {
            "tool": "cloud-posture-watch",
            "format": args.format,
        }
    }

    if args.format in ("markdown", "both"):
        _write_text(output_dir / "posture-report.md", report_md)
    if args.format in ("json", "both"):
        _write_json(output_dir / "posture-report.json", report_json)

    # Existing companion artifact path should also honor --output-dir.
    _write_json(output_dir / "posture-report.meta.json", companion_json)


if __name__ == "__main__":
    main()
