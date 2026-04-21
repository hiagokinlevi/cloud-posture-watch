from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reports.sarif_exporter import export_sarif


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--json-output", dest="json_output", help="Write findings JSON to file")
    parser.add_argument("--sarif-output", dest="sarif_output", help="Write findings as SARIF v2.1.0 to file")
    return parser


def _load_or_generate_findings(args: argparse.Namespace):
    # Minimal compatibility path: if JSON output path exists, reuse it as source;
    # otherwise use an empty findings payload placeholder.
    if args.json_output and Path(args.json_output).exists():
        return json.loads(Path(args.json_output).read_text(encoding="utf-8"))
    return {"findings": []}


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    findings_payload = _load_or_generate_findings(args)

    if args.sarif_output:
        export_sarif(findings_payload, args.sarif_output)

    if args.json_output and not Path(args.json_output).exists():
        Path(args.json_output).write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
