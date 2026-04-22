from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzers.exposure import analyze_exposure
from analyzers.logging import analyze_logging
from analyzers.drift import analyze_drift

from providers.aws import collect_aws
from providers.azure import collect_azure
from providers.gcp import collect_gcp


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-posture-watch",
        description="Cloud posture assessment for AWS, Azure, and GCP.",
    )
    parser.add_argument("--baseline", default="standard", help="Baseline profile name")
    parser.add_argument("--out", default="reports/posture-report.json", help="Output report path")
    parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp"],
        help="Run only one provider collector/analyzer path (aws|azure|gcp)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    requested_provider = args.provider
    provider_order = ["aws", "azure", "gcp"]

    collectors = {
        "aws": collect_aws,
        "azure": collect_azure,
        "gcp": collect_gcp,
    }

    provider_data: Dict[str, Any] = {}
    skipped_providers: Dict[str, str] = {}

    for provider in provider_order:
        if requested_provider and provider != requested_provider:
            skipped_providers[provider] = f"skipped: provider filter active ({requested_provider})"
            continue
        provider_data[provider] = collectors[provider]()

    findings: Dict[str, Any] = {
        "exposure": analyze_exposure(provider_data, baseline=args.baseline),
        "logging": analyze_logging(provider_data, baseline=args.baseline),
        "drift": analyze_drift(provider_data, baseline=args.baseline),
    }

    report: Dict[str, Any] = {
        "metadata": {
            "generated_at": _utc_now(),
            "baseline": args.baseline,
            "provider_scope": requested_provider or "all",
            "active_providers": list(provider_data.keys()),
            "skipped_providers": skipped_providers,
        },
        "providers": provider_data,
        "findings": findings,
    }

    _write_json(Path(args.out), report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
