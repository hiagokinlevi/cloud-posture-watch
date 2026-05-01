#!/usr/bin/env python3
"""cloud-posture-watch CLI entrypoint."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Optional

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _style(text: str, code: str, color_enabled: bool = True) -> str:
    if not color_enabled:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def render_status(message: str, *, color_enabled: bool = True) -> str:
    return _style(message, "32", color_enabled=color_enabled)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-posture-watch",
        description="Cloud security posture assessment for AWS, Azure, and GCP.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color/styling in console output.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    color_enabled = not args.no_color

    if args.version:
        print("cloud-posture-watch")
        return 0

    print(render_status("cloud-posture-watch: scan complete", color_enabled=color_enabled))
    return 0


if __name__ == "__main__":
    sys.exit(main())
