from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List


def _discover_baseline_profiles(baselines_dir: Path) -> Dict[str, List[str]]:
    if not baselines_dir.exists() or not baselines_dir.is_dir():
        raise FileNotFoundError(f"Baselines directory not found: {baselines_dir}")

    discovered: Dict[str, List[str]] = {}
    for provider_dir in sorted(p for p in baselines_dir.iterdir() if p.is_dir()):
        names = sorted(
            p.stem
            for p in provider_dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
        )
        if names:
            discovered[provider_dir.name] = names

    if not discovered:
        raise RuntimeError(f"No baseline profiles discovered in: {baselines_dir}")

    return discovered


def _print_baselines(discovered: Dict[str, List[str]], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"baselines": discovered}, sort_keys=True))
        return

    for provider in sorted(discovered):
        for profile in discovered[provider]:
            print(f"{provider}/{profile}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument(
        "--list-baselines",
        action="store_true",
        help="List discovered baseline profiles and exit",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_baselines:
        baselines_dir = Path(__file__).resolve().parent / "baselines"
        try:
            discovered = _discover_baseline_profiles(baselines_dir)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1
        _print_baselines(discovered, as_json=args.json)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
