from __future__ import annotations

import argparse
import sys
from typing import Iterable, List, Optional, Set

VALID_PROVIDERS = {"aws", "azure", "gcp"}


def _parse_provider_args(values: Optional[Iterable[str]]) -> Optional[Set[str]]:
    """Parse repeatable and/or comma-separated provider values.

    Returns:
        None when omitted (means all providers/default behavior), otherwise a validated set.
    """
    if not values:
        return None

    parsed: Set[str] = set()
    invalid: Set[str] = set()

    for raw in values:
        for token in raw.split(","):
            p = token.strip().lower()
            if not p:
                continue
            if p in VALID_PROVIDERS:
                parsed.add(p)
            else:
                invalid.add(p)

    if invalid:
        raise ValueError(
            f"Invalid provider(s): {', '.join(sorted(invalid))}. "
            f"Valid values: {', '.join(sorted(VALID_PROVIDERS))}."
        )

    if not parsed:
        raise ValueError(
            f"No valid providers supplied. Valid values: {', '.join(sorted(VALID_PROVIDERS))}."
        )

    return parsed


def _run_collectors(selected_providers: Optional[Set[str]] = None) -> List[str]:
    """Minimal orchestration hook for provider-scoped execution.

    In real scans, this controls which provider collectors/analyzers execute.
    Returns executed provider names for deterministic testing.
    """
    providers = ["aws", "azure", "gcp"]
    if selected_providers is not None:
        providers = [p for p in providers if p in selected_providers]

    executed: List[str] = []
    for provider in providers:
        # Placeholder for existing provider-specific collector/analyzer calls.
        executed.append(provider)
    return executed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-posture-watch",
        description="Cloud posture scanner for AWS, Azure, and GCP.",
    )
    parser.add_argument(
        "--provider",
        action="append",
        default=None,
        metavar="PROVIDER[,PROVIDER...]",
        help=(
            "Limit scan scope to selected cloud providers. Repeat flag or pass comma-separated "
            "values (aws, azure, gcp). Omit to scan all providers."
        ),
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        selected = _parse_provider_args(args.provider)
    except ValueError as exc:
        parser.error(str(exc))

    _run_collectors(selected)
    return 0


if __name__ == "__main__":
    sys.exit(main())
