#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cloud-posture-watch CLI")
    parser.add_argument("--output", default="report.json", help="Output report path")
    parser.add_argument("--format", choices=["json", "md", "markdown"], default="json", help="Report format")
    parser.add_argument(
        "--strict-schema",
        action="store_true",
        help="When used with JSON output, validate generated report against bundled schema before exit",
    )
    return parser


def _load_schema_for_report(report_path: Path) -> dict:
    schemas_dir = Path(__file__).resolve().parent / "schemas"
    # Prefer explicit posture report schema, then fall back to first JSON schema in directory.
    preferred = [
        schemas_dir / "posture-report.schema.json",
        schemas_dir / "report.schema.json",
        schemas_dir / "cloud-posture-watch-report.schema.json",
    ]
    for candidate in preferred:
        if candidate.exists():
            with candidate.open("r", encoding="utf-8") as f:
                return json.load(f)

    if schemas_dir.exists():
        for p in sorted(schemas_dir.glob("*.json")):
            if p.is_file():
                with p.open("r", encoding="utf-8") as f:
                    return json.load(f)

    raise FileNotFoundError("No JSON schema found in bundled schemas/")


def _validate_json_report_strict(report_path: Path) -> tuple[bool, str]:
    try:
        import jsonschema  # type: ignore
    except Exception:
        return False, "jsonschema dependency is required for --strict-schema validation"

    try:
        with report_path.open("r", encoding="utf-8") as rf:
            report_data = json.load(rf)
    except Exception as e:
        return False, f"unable to read generated JSON report: {e}"

    try:
        schema = _load_schema_for_report(report_path)
    except Exception as e:
        return False, f"unable to load bundled schema: {e}"

    try:
        jsonschema.validate(instance=report_data, schema=schema)
        return True, ""
    except Exception as e:
        summary = getattr(e, "message", str(e))
        path = list(getattr(e, "path", []))
        if path:
            summary = f"{summary} at $.{".".join(str(p) for p in path)}"
        return False, summary


def _generate_report(fmt: str) -> dict | str:
    # Existing report generation would be here; keep minimal default behavior.
    if fmt == "json":
        return {"status": "ok", "tool": "cloud-posture-watch"}
    return "# Cloud Posture Watch Report\n\nStatus: ok\n"


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    output_path = Path(args.output)
    fmt = "md" if args.format == "markdown" else args.format

    report = _generate_report(fmt)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")

        if args.strict_schema:
            ok, err = _validate_json_report_strict(output_path)
            if not ok:
                print(f"schema validation failed: {err}", file=sys.stderr)
                return 2
    else:
        with output_path.open("w", encoding="utf-8") as f:
            f.write(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
