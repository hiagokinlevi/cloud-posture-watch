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
    write_github_outputs,
)


def test_validate_command_rejects_unknown_subcommand() -> None:
    with pytest.raises(ValueError, match="Unsupported command"):
        validate_command("rm -rf")


def test_parse_action_args_rejects_root_level_provider_and_output_dir_flags() -> None:
    with pytest.raises(ValueError, match="dedicated action inputs"):
        parse_action_args("--provider aws --fail-on high")

    with pytest.raises(ValueError, match="dedicated action inputs"):
        parse_action_args("--output-dir ./tmp")


def test_parse_action_args_rejects_equals_style_root_flags() -> None:
    with pytest.raises(ValueError, match=r"Do not pass --provider"):
        parse_action_args("--provider=aws --fail-on high")

    with pytest.raises(ValueError, match=r"Do not pass --output-dir"):
        parse_action_args("--output-dir=./tmp")


def test_parse_action_args_allows_scan_providers_flag() -> None:
    assert parse_action_args("--providers aws,gcp --fail-on high") == [
        "--providers",
        "aws,gcp",
        "--fail-on",
        "high",
    ]


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
    (workspace / "repo").mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    workdir = resolve_working_directory("repo")
    output_dir = resolve_output_directory("./artifacts", workdir)

    assert workdir == (workspace / "repo").resolve()
    assert output_dir == (workspace / "repo" / "artifacts").resolve()


def test_resolve_working_directory_rejects_parent_traversal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    with pytest.raises(ValueError, match="Working directory must stay within the GitHub workspace"):
        resolve_working_directory("../outside")


def test_resolve_working_directory_rejects_missing_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    with pytest.raises(ValueError, match="Working directory does not exist"):
        resolve_working_directory("missing-repo")


def test_resolve_working_directory_rejects_file_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    file_path = workspace / "not-a-dir"
    file_path.write_text("x", encoding="utf-8")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    with pytest.raises(ValueError, match="Working directory is not a directory"):
        resolve_working_directory("not-a-dir")


def test_resolve_output_directory_rejects_absolute_escape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    workdir = resolve_working_directory(".")

    with pytest.raises(ValueError, match="Output directory must stay within the GitHub workspace"):
        resolve_output_directory(str(tmp_path / "outside"), workdir)


def test_discover_report_outputs_returns_newest_report_per_extension(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

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


def test_discover_report_outputs_ignores_symlink_escape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    output_dir = workspace / "output"
    workspace.mkdir()
    output_dir.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    markdown_report = output_dir / "posture_aws_20260410_010101.md"
    markdown_report.write_text("safe", encoding="utf-8")

    outside_report = tmp_path / "outside.md"
    outside_report.write_text("secret", encoding="utf-8")
    escaped_report = output_dir / "posture_aws_20260410_020202.md"
    escaped_report.symlink_to(outside_report)

    outputs = discover_report_outputs(output_dir)

    assert outputs["report_markdown"] == str(markdown_report.resolve())


def test_write_github_outputs_uses_multiline_format_for_newline_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output_file = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    write_github_outputs({"report_markdown": "safe\ninjected=value"})

    contents = output_file.read_text(encoding="utf-8")
    assert contents.startswith("report_markdown<<CPW_OUTPUT_")
    assert "safe\ninjected=value\nCPW_OUTPUT_" in contents
    assert "report_markdown=safe" not in contents
