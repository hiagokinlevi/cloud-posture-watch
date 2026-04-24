from __future__ import annotations

import argparse
import sys
from importlib import metadata as importlib_metadata


def _get_version_text() -> str:
    package_name = "cloud-posture-watch"
    try:
        version = importlib_metadata.version(package_name)
        return f"{package_name} {version}"
    except importlib_metadata.PackageNotFoundError:
        return f"{package_name} (version metadata unavailable)"


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
    args = parser.parse_args(argv)

    if args.version:
        print(_get_version_text())
        return 0

    # Existing scan execution path remains unchanged in this bounded increment.
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
