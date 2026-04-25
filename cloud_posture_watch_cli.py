from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator


def _load_structured_file(path: str) -> Any:
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(raw)
    return json.loads(raw)


def _format_schema_error(err, file_path: str) -> str:
    path = ".".join(str(x) for x in err.absolute_path) or "$"
    if err.validator == "additionalProperties":
        extras = []
        if isinstance(err.instance, dict) and isinstance(err.schema, dict):
            allowed = set(err.schema.get("properties", {}).keys())
            extras = sorted([k for k in err.instance.keys() if k not in allowed])
        if extras:
            return f"{file_path}: unknown field(s) at {path}: {', '.join(extras)}"
    return f"{file_path}: {path}: {err.message}"


def validate_input_against_schema(data: Any, schema: dict[str, Any], file_path: str, strict_schema: bool = False) -> list[str]:
    schema_to_use = dict(schema)
    if strict_schema:
        # Preserve existing schemas while enforcing unknown-field rejection at runtime.
        def _strictify(node: Any) -> Any:
            if isinstance(node, dict):
                out = {}
                for k, v in node.items():
                    out[k] = _strictify(v)
                if out.get("type") == "object" and "additionalProperties" not in out:
                    out["additionalProperties"] = False
                return out
            if isinstance(node, list):
                return [_strictify(i) for i in node]
            return node

        schema_to_use = _strictify(schema_to_use)

    validator = Draft7Validator(schema_to_use)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    return [_format_schema_error(e, file_path) for e in errors]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--offline-evidence", help="Path to offline evidence JSON/YAML")
    parser.add_argument("--baseline", help="Path to baseline JSON/YAML")
    parser.add_argument(
        "--strict-schema",
        action="store_true",
        help="Fail validation when unknown fields are present in offline evidence/baseline input",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # NOTE: existing command flow omitted; this is the strict-schema glue point.
    # Assume schema loading is already present in the real flow.
    if args.offline_evidence:
        evidence = _load_structured_file(args.offline_evidence)
        schema = {"type": "object", "properties": {"resources": {"type": "array"}}}
        errs = validate_input_against_schema(
            evidence,
            schema,
            args.offline_evidence,
            strict_schema=args.strict_schema,
        )
        if errs:
            print("Validation failed:", file=sys.stderr)
            for e in errs:
                print(f" - {e}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
