"""Validated entrypoint for the Marketplace-ready GitHub Action."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path
from uuid import uuid4


SUPPORTED_COMMANDS = {
    "assess",
    "drift",
    "report",
    "scan",
    "scan-azure-nsgs",
    "scan-gcp-firewalls",
    "scan-aws-iam",
    "scan-aws-rds",
    "scan-aws-secrets",
    "scan-azure-sql",
    "scan-gcp-cloud-sql",
    "scan-gcp-iam",
    "scan-azure-rbac",
    "scan-iam-comparison",
    "list-checks",
    "json-schema",
    "notify-webhook",
    "watch-report",
}

FORBIDDEN_ARG_TOKENS = {"--provider", "--output-dir"}
REPORT_PATTERNS = {
    "report_markdown": "posture_*.md",
    "report_json": "posture_*.json",
    "report_html": "posture_*.html",
}


def _resolve_workspace_root() -> Path:
    """Return the resolved GitHub workspace root for path validation."""
    return Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()


def _ensure_within_workspace(path: Path, *, label: str, workspace: Path) -> Path:
    """Reject action inputs that resolve outside the workflow workspace."""
    try:
        path.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} must stay within the GitHub workspace: {workspace}") from exc
    return path


def parse_action_args(raw_args: str) -> list[str]:
    """Split a GitHub Action input string into CLI tokens."""
    try:
        tokens = shlex.split(raw_args, posix=True)
    except ValueError as exc:
        raise ValueError(f"Unable to parse args: {exc}") from exc
    forbidden = []
    for token in tokens:
        matched = next(
            (
                reserved
                for reserved in FORBIDDEN_ARG_TOKENS
                if token == reserved or token.startswith(f"{reserved}=")
            ),
            None,
        )
        if matched:
            forbidden.append(matched)
    if forbidden:
        joined = ", ".join(sorted(set(forbidden)))
        raise ValueError(
            f"Do not pass {joined} in args; use the dedicated action inputs instead."
        )
    return tokens


def validate_command(command: str) -> str:
    """Ensure the requested subcommand is explicitly supported."""
    normalized = command.strip()
    if not normalized:
        raise ValueError("Action input 'command' is required.")
    if normalized not in SUPPORTED_COMMANDS:
        supported = ", ".join(sorted(SUPPORTED_COMMANDS))
        raise ValueError(f"Unsupported command '{normalized}'. Supported commands: {supported}")
    return normalized


def resolve_working_directory(raw_workdir: str) -> Path:
    """Resolve the command working directory against the workflow workspace."""
    workspace = _resolve_workspace_root()
    path = Path(raw_workdir)
    if not path.is_absolute():
        path = workspace / path
    return _ensure_within_workspace(path.resolve(), label="Working directory", workspace=workspace)


def resolve_output_directory(raw_output_dir: str, workdir: Path) -> Path:
    """Resolve the report output directory relative to the working directory."""
    workspace = _resolve_workspace_root()
    path = Path(raw_output_dir)
    if not path.is_absolute():
        path = workdir / path
    return _ensure_within_workspace(path.resolve(), label="Output directory", workspace=workspace)


def build_command(
    *,
    subcommand: str,
    raw_args: str,
    provider: str,
    output_dir: Path,
) -> list[str]:
    """Construct the validated k1n-posture command."""
    command = validate_command(subcommand)
    extra_args = parse_action_args(raw_args)

    if command == "scan":
        return [
            "k1n-posture",
            command,
            "--output-dir",
            str(output_dir),
            *extra_args,
        ]

    return [
        "k1n-posture",
        "--provider",
        provider,
        "--output-dir",
        str(output_dir),
        command,
        *extra_args,
    ]


def discover_report_outputs(output_dir: Path) -> dict[str, str]:
    """Return the newest posture report path for each known report extension."""
    results = {key: "" for key in REPORT_PATTERNS}
    for key, pattern in REPORT_PATTERNS.items():
        candidates = sorted(output_dir.glob(pattern), key=lambda item: item.stat().st_mtime)
        if candidates:
            results[key] = str(candidates[-1].resolve())
    return results


def write_github_outputs(outputs: dict[str, str]) -> None:
    """Append output variables when running inside GitHub Actions."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with Path(output_path).open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            delimiter = f"CPW_OUTPUT_{uuid4().hex}"
            while delimiter in value:
                delimiter = f"CPW_OUTPUT_{uuid4().hex}"
            handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")


def main(argv: list[str] | None = None) -> int:
    """Run the requested CLI command and expose generated report paths."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True, help="Supported k1n-posture subcommand.")
    parser.add_argument("--args", default="", help="Additional arguments for the subcommand.")
    parser.add_argument("--provider", default="aws", help="Cloud provider root option.")
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Directory where reports should be written.",
    )
    parser.add_argument(
        "--working-directory",
        default=".",
        help="Directory where the CLI command should run.",
    )
    parsed = parser.parse_args(argv)

    try:
        workdir = resolve_working_directory(parsed.working_directory)
        output_dir = resolve_output_directory(parsed.output_dir, workdir)
        command = build_command(
            subcommand=parsed.command,
            raw_args=parsed.args,
            provider=parsed.provider,
            output_dir=output_dir,
        )
    except ValueError as exc:
        print(f"Action input error: {exc}", file=sys.stderr)
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(command, cwd=workdir, check=False)
    outputs = {
        "command": shlex.join(command),
        "working_directory": str(workdir),
        "output_directory": str(output_dir),
        "exit_code": str(completed.returncode),
        **discover_report_outputs(output_dir),
    }
    write_github_outputs(outputs)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
