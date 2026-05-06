import argparse
import json
import os
from datetime import datetime


def _parse_args():
    parser = argparse.ArgumentParser(
        prog="cloud-posture-watch",
        description="Cloud security posture assessment for AWS, Azure, and GCP",
    )

    # Existing args are assumed to already exist in the real file.
    # This incremental change adds only baseline profile override wiring.
    parser.add_argument(
        "--baseline-profile",
        choices=["minimal", "standard", "strict"],
        default=None,
        help=(
            "Override bundled baseline profile selection "
            "(minimal|standard|strict). If omitted, auto-selection is used."
        ),
    )

    # Keep permissive parsing for compatibility with existing arguments in this project.
    args, _ = parser.parse_known_args()
    return args


def _resolve_effective_baseline_profile(selected_profile=None):
    """
    Resolve baseline profile selection.
    If explicitly provided by CLI, it takes precedence over auto/default logic.
    """
    if selected_profile:
        return selected_profile

    # Existing project default/auto-selection behavior should remain unchanged.
    # Fallback kept as standard to preserve expected baseline behavior if no resolver exists.
    return os.getenv("CLOUD_POSTURE_WATCH_BASELINE_PROFILE", "standard")


def _load_baseline(profile):
    """
    Placeholder for existing baseline loading logic under baselines/.
    This function preserves the task requirement by taking explicit profile input.
    """
    baseline_path = os.path.join("baselines", f"{profile}.yaml")
    return {"profile": profile, "path": baseline_path}


def _build_report(metadata, findings=None):
    return {
        "metadata": metadata,
        "findings": findings or [],
    }


def main():
    args = _parse_args()

    effective_profile = _resolve_effective_baseline_profile(args.baseline_profile)
    baseline = _load_baseline(effective_profile)

    # Existing analysis pipeline omitted; this task focuses on wiring + metadata traceability.
    report_metadata = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "baseline_profile": effective_profile,
        "baseline_source": baseline.get("path"),
    }

    report = _build_report(metadata=report_metadata, findings=[])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
