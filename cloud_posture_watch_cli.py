#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

import yaml


class BaselineValidationError(Exception):
    """Raised when baseline validation fails."""


def _type_name(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__


def _expected_type_name(schema_type):
    if isinstance(schema_type, list):
        return " or ".join(str(t) for t in schema_type)
    return str(schema_type)


def _validate_node(data, schema, file_path, key_path="$"):
    if not isinstance(schema, dict):
        return

    expected_type = schema.get("type")

    if expected_type == "object":
        if not isinstance(data, dict):
            raise BaselineValidationError(
                f"Baseline validation failed: file={file_path}, key={key_path}, "
                f"expected type=object, actual type={_type_name(data)}"
            )

        properties = schema.get("properties", {})
        required = schema.get("required", [])

        for req_key in required:
            if req_key not in data:
                raise BaselineValidationError(
                    f"Baseline validation failed: file={file_path}, key={key_path}.{req_key}, "
                    "expected key is required but missing"
                )

        additional_properties = schema.get("additionalProperties", True)
        if additional_properties is False:
            unknown = [k for k in data.keys() if k not in properties]
            if unknown:
                bad = unknown[0]
                raise BaselineValidationError(
                    f"Baseline validation failed: file={file_path}, key={key_path}.{bad}, "
                    "unexpected key not allowed by schema"
                )

        for prop, prop_schema in properties.items():
            if prop in data:
                _validate_node(data[prop], prop_schema, file_path, f"{key_path}.{prop}")

    elif expected_type == "array":
        if not isinstance(data, list):
            raise BaselineValidationError(
                f"Baseline validation failed: file={file_path}, key={key_path}, "
                f"expected type=array, actual type={_type_name(data)}"
            )

        item_schema = schema.get("items")
        if item_schema:
            for idx, item in enumerate(data):
                _validate_node(item, item_schema, file_path, f"{key_path}[{idx}]")

    elif expected_type:
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "null": type(None),
        }

        expected_python = type_map.get(expected_type)
        if expected_python and not isinstance(data, expected_python):
            raise BaselineValidationError(
                f"Baseline validation failed: file={file_path}, key={key_path}, "
                f"expected type={_expected_type_name(expected_type)}, actual type={_type_name(data)}"
            )


def validate_baseline_file_against_schema(baseline_file, schema_file):
    baseline_path = Path(baseline_file)
    schema_path = Path(schema_file)

    if not baseline_path.exists():
        raise BaselineValidationError(f"Baseline file not found: {baseline_file}")
    if not schema_path.exists():
        raise BaselineValidationError(f"Schema file not found: {schema_file}")

    with baseline_path.open("r", encoding="utf-8") as bf:
        baseline_data = yaml.safe_load(bf) or {}

    with schema_path.open("r", encoding="utf-8") as sf:
        schema_data = json.load(sf)

    _validate_node(baseline_data, schema_data, str(baseline_path), "$")


def _default_schema_for_provider(provider):
    base = Path(__file__).resolve().parent
    return str(base / "schemas" / f"{provider}_baseline.schema.json")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="cloud-posture-watch CLI")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp"], required=True)
    parser.add_argument("--baseline", required=True, help="Path to baseline YAML")
    parser.add_argument("--baseline-schema", default=None, help="Optional baseline schema path")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    schema_path = args.baseline_schema or _default_schema_for_provider(args.provider)

    try:
        validate_baseline_file_against_schema(args.baseline, schema_path)
    except BaselineValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    # existing execution path continues here in real project
    print("Baseline validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
