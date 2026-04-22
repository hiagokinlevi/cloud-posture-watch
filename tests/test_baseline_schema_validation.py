import json

import yaml

from cloud_posture_watch_cli import BaselineValidationError, validate_baseline_file_against_schema


def test_baseline_schema_validation_passes(tmp_path):
    schema = {
        "type": "object",
        "properties": {
            "exposure": {
                "type": "object",
                "properties": {"allow_public_buckets": {"type": "boolean"}},
                "required": ["allow_public_buckets"],
                "additionalProperties": False,
            }
        },
        "required": ["exposure"],
        "additionalProperties": False,
    }
    baseline = {"exposure": {"allow_public_buckets": False}}

    schema_file = tmp_path / "schema.json"
    baseline_file = tmp_path / "baseline.yaml"
    schema_file.write_text(json.dumps(schema), encoding="utf-8")
    baseline_file.write_text(yaml.safe_dump(baseline), encoding="utf-8")

    validate_baseline_file_against_schema(str(baseline_file), str(schema_file))


def test_baseline_schema_validation_fails_with_actionable_message(tmp_path):
    schema = {
        "type": "object",
        "properties": {
            "exposure": {
                "type": "object",
                "properties": {"allow_public_buckets": {"type": "boolean"}},
                "required": ["allow_public_buckets"],
                "additionalProperties": False,
            }
        },
        "required": ["exposure"],
        "additionalProperties": False,
    }
    baseline = {"exposure": {"allow_public_buckets": "no"}}

    schema_file = tmp_path / "schema.json"
    baseline_file = tmp_path / "baseline.yaml"
    schema_file.write_text(json.dumps(schema), encoding="utf-8")
    baseline_file.write_text(yaml.safe_dump(baseline), encoding="utf-8")

    try:
        validate_baseline_file_against_schema(str(baseline_file), str(schema_file))
        assert False, "Expected BaselineValidationError"
    except BaselineValidationError as exc:
        msg = str(exc)
        assert "file=" in msg
        assert "key=$.exposure.allow_public_buckets" in msg
        assert "expected type=boolean" in msg
