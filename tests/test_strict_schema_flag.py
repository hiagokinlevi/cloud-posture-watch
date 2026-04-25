from cloud_posture_watch_cli import validate_input_against_schema


def test_strict_schema_flag_pass_and_fail_behavior():
    schema = {
        "type": "object",
        "properties": {
            "resources": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                },
            }
        },
    }

    payload_with_unknown = {
        "resources": [{"id": "r-1", "unexpected": True}],
        "extra_top_level": "boom",
    }

    permissive = validate_input_against_schema(payload_with_unknown, schema, "evidence.yaml", strict_schema=False)
    assert permissive == []

    strict = validate_input_against_schema(payload_with_unknown, schema, "evidence.yaml", strict_schema=True)
    assert strict
    joined = "\n".join(strict)
    assert "evidence.yaml" in joined
    assert "unknown field" in joined
    assert "extra_top_level" in joined or "unexpected" in joined
