"""
Tests for JSON, HTML, and SARIF report serializers plus cli/posture_report_cmd.py.

Validates:
  - JSON report structure, schema_version, field presence
  - HTML report is valid HTML with expected content
  - SARIF report structure is valid and includes stable rule/result metadata
  - Risk score calculation
  - save_json_report / save_html_report / save_sarif_report write to disk correctly
  - posture_report_cmd CLI: parses input JSON, generates output files,
    fail-on gate exits non-zero, missing file raises ClickException
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from reports.posture_report_html import generate_html_report, save_html_report
from reports.posture_report_json import (
    SCHEMA_VERSION,
    generate_json_report,
    save_json_report,
)
from reports.posture_report_sarif import (
    SARIF_VERSION,
    generate_sarif_report,
    save_sarif_report,
)
from reports.posture_report_schema import (
    JSON_SCHEMA_ID,
    POSTURE_REPORT_JSON_SCHEMA,
    validate_posture_report_json_contract,
)
from schemas.posture import (
    DriftItem,
    Importance,
    PostureFinding,
    PostureReport,
    Provider,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)


def _finding(
    severity: Severity = Severity.HIGH,
    resource: str = "my-bucket",
    flag: str = "TEST_FLAG",
) -> PostureFinding:
    return PostureFinding(
        provider=Provider.AWS,
        resource_type="s3_bucket",
        resource_name=resource,
        severity=severity,
        flag=flag,
        title=f"Test finding ({severity.value})",
        recommendation="Test recommendation text.",
    )


def _drift(resource: str = "bucket-a") -> DriftItem:
    return DriftItem(
        provider=Provider.AWS,
        resource_type="s3_bucket",
        resource_name=resource,
        baseline_name="standard",
        control="logging_enabled",
        expected=True,
        actual=False,
        importance=Importance.REQUIRED,
        severity=Severity.HIGH,
    )


def _report(
    findings: list[PostureFinding] | None = None,
    drift: list[DriftItem] | None = None,
    total: int = 5,
) -> PostureReport:
    return PostureReport(
        run_id="test1234",
        provider=Provider.AWS,
        baseline_name="standard",
        total_resources=total,
        findings=findings or [],
        drift_items=drift or [],
        assessed_at=_TS,
    )


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

class TestGenerateJsonReport:

    def test_returns_valid_json(self):
        doc = generate_json_report(_report())
        parsed = json.loads(doc)
        assert isinstance(parsed, dict)

    def test_schema_version_present(self):
        parsed = json.loads(generate_json_report(_report()))
        assert parsed["schema_version"] == SCHEMA_VERSION

    def test_schema_id_present(self):
        parsed = json.loads(generate_json_report(_report()))
        assert parsed["$schema"] == JSON_SCHEMA_ID

    def test_generated_report_matches_stable_contract(self):
        r = _report(findings=[_finding()], drift=[_drift()])
        parsed = json.loads(generate_json_report(r))
        assert validate_posture_report_json_contract(parsed) == []

    def test_contract_validator_reports_missing_fields(self):
        parsed = json.loads(generate_json_report(_report()))
        parsed.pop("findings")
        assert validate_posture_report_json_contract(parsed) == [
            "missing required top-level field: findings",
            "findings must be an array",
        ]

    def test_machine_readable_schema_exports_required_v1_fields(self):
        required = POSTURE_REPORT_JSON_SCHEMA["required"]
        for key in [
            "$schema",
            "schema_version",
            "risk_score",
            "risk_level",
            "risk_model",
            "finding_counts",
            "findings",
            "drift_items",
        ]:
            assert key in required

    def test_provider_present(self):
        parsed = json.loads(generate_json_report(_report()))
        assert parsed["provider"] == "aws"

    def test_findings_array_present(self):
        r = _report(findings=[_finding()])
        parsed = json.loads(generate_json_report(r))
        assert len(parsed["findings"]) == 1

    def test_drift_array_present(self):
        r = _report(drift=[_drift()])
        parsed = json.loads(generate_json_report(r))
        assert len(parsed["drift_items"]) == 1

    def test_risk_score_in_range(self):
        r = _report(findings=[_finding(Severity.CRITICAL)])
        parsed = json.loads(generate_json_report(r))
        assert 0 <= parsed["risk_score"] <= 100

    def test_risk_score_zero_no_findings(self):
        r = _report()
        parsed = json.loads(generate_json_report(r))
        assert parsed["risk_score"] == 0

    def test_risk_score_capped_at_100(self):
        findings = [_finding(Severity.CRITICAL)] * 20  # 20 * 10 = 200 → cap at 100
        r = _report(findings=findings)
        parsed = json.loads(generate_json_report(r))
        assert parsed["risk_score"] == 100

    def test_risk_level_present(self):
        r = _report(findings=[_finding(Severity.CRITICAL)] * 6)
        parsed = json.loads(generate_json_report(r))
        assert parsed["risk_level"] == "high"

    def test_risk_model_exports_severity_weights(self):
        parsed = json.loads(generate_json_report(_report()))
        assert parsed["risk_model"]["severity_weights"]["critical"] == 10
        assert parsed["risk_model"]["max_score"] == 100

    def test_finding_has_required_keys(self):
        r = _report(findings=[_finding()])
        parsed = json.loads(generate_json_report(r))
        f = parsed["findings"][0]
        for key in ["provider", "resource_type", "resource_name", "severity",
                    "flag", "title", "recommendation"]:
            assert key in f

    def test_assessed_at_present(self):
        parsed = json.loads(generate_json_report(_report()))
        assert "assessed_at" in parsed
        assert "2026" in parsed["assessed_at"]

    def test_finding_counts_present(self):
        r = _report(findings=[_finding(Severity.HIGH), _finding(Severity.MEDIUM)])
        parsed = json.loads(generate_json_report(r))
        assert parsed["finding_counts"]["high"] == 1
        assert parsed["finding_counts"]["medium"] == 1

    def test_compact_output(self):
        doc = generate_json_report(_report(), indent=0)
        assert "\n" not in doc.strip()


class TestSaveJsonReport:

    def test_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = _report(findings=[_finding()])
            path = save_json_report(r, tmpdir)
            assert path.exists()
            assert path.suffix == ".json"

    def test_file_contains_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = _report(findings=[_finding()])
            path = save_json_report(r, tmpdir)
            parsed = json.loads(path.read_text())
            assert parsed["provider"] == "aws"

    def test_creates_directory_if_absent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = Path(tmpdir) / "subdir" / "reports"
            r = _report()
            save_json_report(r, new_dir)
            assert new_dir.exists()


# ---------------------------------------------------------------------------
# SARIF report
# ---------------------------------------------------------------------------

class TestGenerateSarifReport:

    def test_returns_valid_sarif_json(self):
        parsed = json.loads(generate_sarif_report(_report(findings=[_finding()])))

        assert parsed["version"] == SARIF_VERSION
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "cloud-posture-watch"

    def test_includes_rules_for_findings_and_drift(self):
        parsed = json.loads(generate_sarif_report(_report(findings=[_finding()], drift=[_drift()])))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {rule["id"] for rule in rules}

        assert "TEST_FLAG" in rule_ids
        assert "DRIFT-logging_enabled" in rule_ids

    def test_includes_synthetic_locations_and_fingerprints(self):
        parsed = json.loads(generate_sarif_report(_report(findings=[_finding(resource="prod-bucket")])))
        result = parsed["runs"][0]["results"][0]

        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(
            "aws/s3_bucket/prod-bucket.json"
        )
        assert "primaryLocationLineHash" in result["partialFingerprints"]


class TestSaveSarifReport:

    def test_creates_sarif_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_sarif_report(_report(findings=[_finding()]), tmpdir)

            assert path.exists()
            assert path.suffix == ".sarif"

    def test_saved_file_contains_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_sarif_report(_report(findings=[_finding()]), tmpdir)
            parsed = json.loads(path.read_text())

            assert parsed["runs"][0]["results"][0]["ruleId"] == "TEST_FLAG"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

class TestGenerateHtmlReport:

    def test_returns_string_starting_with_doctype(self):
        html = generate_html_report(_report())
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_contains_provider_name(self):
        html = generate_html_report(_report())
        assert "AWS" in html

    def test_contains_run_id(self):
        r = _report()
        html = generate_html_report(r)
        assert r.run_id in html

    def test_contains_finding_title(self):
        r = _report(findings=[_finding(Severity.CRITICAL)])
        html = generate_html_report(r)
        assert "Test finding" in html

    def test_contains_risk_score(self):
        r = _report(findings=[_finding(Severity.CRITICAL)])
        html = generate_html_report(r)
        # Risk score for one CRITICAL finding = 10
        assert ">10<" in html

    def test_contains_risk_level(self):
        r = _report(findings=[_finding(Severity.CRITICAL)] * 6)
        html = generate_html_report(r)
        assert "HIGH" in html

    def test_no_external_resources(self):
        """Self-contained report should not link to external CSS/JS."""
        html = generate_html_report(_report())
        assert "http://" not in html
        assert "https://" not in html.replace(
            "https://github.com/hiagokinlevi/cloud-posture-watch", ""
        )

    def test_html_escaping_in_resource_name(self):
        """Resource names with special chars should be HTML-escaped."""
        f = _finding(resource="bucket<script>xss</script>")
        r = _report(findings=[f])
        html = generate_html_report(r)
        assert "<script>xss</script>" not in html
        assert "&lt;script&gt;" in html

    def test_drift_section_present_when_drift_items(self):
        r = _report(drift=[_drift()])
        html = generate_html_report(r)
        assert "Configuration Drift" in html

    def test_no_drift_section_when_empty(self):
        r = _report()
        html = generate_html_report(r)
        assert "Configuration Drift" not in html

    def test_empty_findings_shows_no_findings_message(self):
        r = _report()
        html = generate_html_report(r)
        assert "No findings detected" in html

    def test_severity_badges_present(self):
        r = _report(findings=[
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
        ])
        html = generate_html_report(r)
        assert "CRITICAL" in html
        assert "HIGH" in html


class TestSaveHtmlReport:

    def test_creates_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = _report()
            path = save_html_report(r, tmpdir)
            assert path.exists()
            assert path.suffix == ".html"

    def test_file_is_valid_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = _report(findings=[_finding()])
            path = save_html_report(r, tmpdir)
            content = path.read_text()
            assert "<!DOCTYPE html>" in content


# ---------------------------------------------------------------------------
# posture_report_cmd CLI
# ---------------------------------------------------------------------------

class TestPostureReportCmd:

    def _write_findings_json(self, tmpdir: str, findings: list[PostureFinding]) -> Path:
        """Write a findings JSON file and return its path."""
        r = _report(findings=findings)
        return save_json_report(r, tmpdir)

    def test_generates_json_output(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Write input file
            r = _report(findings=[_finding()])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "json", "--output-dir", "./out"],
            )
            assert result.exit_code == 0, result.output
            assert "JSON report" in result.output

    def test_generates_html_output(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding()])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "html", "--output-dir", "./out"],
            )
            assert result.exit_code == 0, result.output
            assert "HTML report" in result.output

    def test_generates_both_formats(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding()])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "both", "--output-dir", "./out"],
            )
            assert result.exit_code == 0, result.output
            assert "JSON report" in result.output
            assert "HTML report" in result.output

    def test_generates_sarif_output(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding()])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "sarif", "--output-dir", "./out"],
            )
            assert result.exit_code == 0, result.output
            assert "SARIF report" in result.output

    def test_generates_all_formats(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding()])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "all", "--output-dir", "./out"],
            )
            assert result.exit_code == 0, result.output
            assert "JSON report" in result.output
            assert "HTML report" in result.output
            assert "SARIF report" in result.output

    def test_summary_line_in_output(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding(Severity.HIGH)])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "json", "--output-dir", "./out"],
            )
            assert "HIGH=1" in result.output

    def test_fail_on_gate_exits_1(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding(Severity.CRITICAL)])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                [
                    "--input", str(input_path),
                    "--format", "json",
                    "--output-dir", "./out",
                    "--fail-on", "high",
                ],
            )
            assert result.exit_code == 1

    def test_fail_on_gate_exits_0_when_no_matching_severity(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding(Severity.LOW)])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                [
                    "--input", str(input_path),
                    "--format", "json",
                    "--output-dir", "./out",
                    "--fail-on", "high",
                ],
            )
            assert result.exit_code == 0

    def test_missing_input_file_raises(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        result = runner.invoke(
            posture_report_cmd,
            ["--input", "/tmp/no_such_file_posture_cmd.json", "--format", "json"],
        )
        assert result.exit_code != 0

    def test_invalid_json_raises(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("bad.json").write_text("not json {{{")
            result = runner.invoke(
                posture_report_cmd,
                ["--input", "bad.json", "--format", "json"],
            )
            assert result.exit_code != 0

    def test_stdout_flag_prints_json(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding()])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "json", "--stdout"],
            )
            assert result.exit_code == 0
            # Output should be parseable as JSON (with the summary line after)
            # Find the JSON part
            output = result.output
            json_start = output.find("{")
            if json_start >= 0:
                json_str = output[json_start:].strip()
                # JSON ends before the summary line
                json_end = json_str.rfind("}") + 1
                parsed = json.loads(json_str[:json_end])
                assert "provider" in parsed

    def test_stdout_flag_prints_sarif(self):
        from cli.posture_report_cmd import posture_report_cmd

        runner = CliRunner()
        with runner.isolated_filesystem():
            r = _report(findings=[_finding()])
            input_path = save_json_report(r, ".")

            result = runner.invoke(
                posture_report_cmd,
                ["--input", str(input_path), "--format", "sarif", "--stdout"],
            )
            assert result.exit_code == 0
            output = result.output
            sarif_start = output.find("{")
            sarif_str = output[sarif_start:].strip()
            sarif_end = sarif_str.rfind("}") + 1
            parsed = json.loads(sarif_str[:sarif_end])
            assert parsed["version"] == SARIF_VERSION

    def test_json_schema_command_prints_schema_contract(self):
        from cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["json-schema"])
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["$id"] == JSON_SCHEMA_ID
        assert parsed["properties"]["schema_version"]["const"] == SCHEMA_VERSION

    def test_root_output_dir_is_used_when_invoked_via_main_cli(self):
        from cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            input_path = save_json_report(_report(findings=[_finding()]), ".")
            result = runner.invoke(
                cli,
                [
                    "--output-dir",
                    "./root-out",
                    "posture-report",
                    "--input",
                    str(input_path),
                    "--format",
                    "sarif",
                ],
            )

            assert result.exit_code == 0, result.output
            assert Path("./root-out").exists()
            assert any(path.suffix == ".sarif" for path in Path("./root-out").iterdir())
