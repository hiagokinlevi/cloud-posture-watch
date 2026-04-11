from __future__ import annotations

from pathlib import Path

import pytest

from scripts.github_action_entrypoint import (
    build_command,
    discover_report_outputs,
    parse_action_args,
    resolve_output_directory,
    resolve_working_directory,
    validate_command,
)


def test_validate_command_rejects_unknown_subcommand() -> None:
    with pytest.raises(ValueError, match="Unsupported command"):
        validate_command("rm -rf")


def test_parse_action_args_rejects_root_level_provider_and_output_dir_flags() -> None:
    with pytest.raises(ValueError, match="dedicated action inputs"):
        parse_action_args("--provider aws --fail-on high")

    with pytest.raises(ValueError, match="dedicated action inputs"):
        parse_action_args("--output-dir ./tmp")


def test_build_command_places_root_options_before_standard_subcommands(tmp_path: Path) -> None:
    command = build_command(
        subcommand="assess",
        raw_args="--profile strict --fail-on high",
        provider="gcp",
        output_dir=tmp_path / "reports",
    )

    assert command == [
        "k1n-posture",
        "--provider",
        "gcp",
        "--output-dir",
        str((tmp_path / "reports").resolve()),
        "assess",
        "--profile",
        "strict",
        "--fail-on",
        "high",
    ]


def test_build_command_places_scan_output_dir_after_subcommand(tmp_path: Path) -> None:
    command = build_command(
        subcommand="scan",
        raw_args="--providers aws,gcp --fail-on high",
        provider="aws",
        output_dir=tmp_path / "scan-output",
    )

    assert command == [
        "k1n-posture",
        "scan",
        "--output-dir",
        str((tmp_path / "scan-output").resolve()),
        "--providers",
        "aws,gcp",
        "--fail-on",
        "high",
    ]


def test_resolve_paths_use_workspace_and_workdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    workdir = resolve_working_directory("repo")
    output_dir = resolve_output_directory("./artifacts", workdir)

    assert workdir == (workspace / "repo").resolve()
    assert output_dir == (workspace / "repo" / "artifacts").resolve()


def test_discover_report_outputs_returns_newest_report_per_extension(tmp_path: Path) -> None:
    markdown_old = tmp_path / "posture_aws_20260410_010101.md"
    markdown_new = tmp_path / "posture_aws_20260410_020202.md"
    json_report = tmp_path / "posture_aws_20260410_020202.json"

    markdown_old.write_text("old", encoding="utf-8")
    markdown_new.write_text("new", encoding="utf-8")
    json_report.write_text("{}", encoding="utf-8")

    outputs = discover_report_outputs(tmp_path)

    assert outputs["report_markdown"] == str(markdown_new.resolve())
    assert outputs["report_json"] == str(json_report.resolve())
    assert outputs["report_html"] == ""
