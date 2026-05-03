#!/usr/bin/env python3
"""CLI entrypoint for cloud-posture-watch."""

from __future__ import annotations

import argparse
import sys

try:
    from importlib.metadata import PackageNotFoundError, version as pkg_version
except Exception:  # pragma: no cover
    PackageNotFoundError = Exception  # type: ignore
    pkg_version = None  # type: ignore


def _resolve_version() -> str:
    """Return installed package version if available, otherwise a safe fallback."""
    package_names = ("cloud-posture-watch", "cloud_posture_watch")
    if pkg_version is not None:
        for name in package_names:
            try:
                return pkg_version(name)
            except PackageNotFoundError:
                continue
            except Exception:
                continue
    return "0.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument(
        "-V",
        "--version",
        action="store_true",
        help="Print installed version and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, remaining = parser.parse_known_args(argv)

    if args.version:
        print(f"cloud-posture-watch {_resolve_version()}")
        return 0

    # Preserve existing behavior by delegating to project CLI implementation.
    # Import is delayed so --version exits without running collectors.
    from cli.main import main as cli_main  # type: ignore

    return int(cli_main(remaining) or 0)


if __name__ == "__main__":
    sys.exit(main())
