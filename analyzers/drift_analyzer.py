"""
Configuration Drift Analyzer
==============================
Compares the live posture of cloud resources against a YAML baseline and
produces a drift report identifying deviations from expected configuration.

A "drift item" represents a single attribute of a single resource that differs
from what the baseline defines as required or recommended.

Drift sensitivity levels
------------------------
The DRIFT_SENSITIVITY env var controls which deviations are reported:
  - low      : Only report deviations from `required` baseline controls
  - medium   : Also report deviations from `recommended` controls
  - high     : Report any deviation, including informational notes

Baseline file structure
-----------------------
Each YAML baseline has a `storage` section with nested provider-specific checks.
See baselines/aws/standard.yaml for the canonical example.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class DriftItem:
    """A single configuration drift finding."""
    provider: str
    resource_type: str
    resource_name: str
    baseline_name: str
    control: str            # The baseline control that was checked
    expected: Any           # The value/state required by the baseline
    actual: Any             # The observed value/state
    importance: str         # "required", "recommended", "informational"
    severity: str           # "high", "medium", "low" (derived from importance + deviation)


# Maps baseline storage control keys to posture object attributes
# Format: baseline_key -> (posture_attribute, expected_value, importance)
_AWS_S3_CONTROL_MAP: dict[str, tuple[str, Any, str]] = {
    "public_access_block_required": ("public_access_blocked", True, "required"),
    "encryption_required": ("encryption_enabled", True, "required"),
    "logging_required": ("logging_enabled", True, "required"),
    "versioning_recommended": ("versioning_enabled", True, "recommended"),
}

_AZURE_STORAGE_CONTROL_MAP: dict[str, tuple[str, Any, str]] = {
    "https_only_required": ("https_only", True, "required"),
    "public_blob_access_denied": ("public_blob_access_allowed", False, "required"),
}

_GCP_GCS_CONTROL_MAP: dict[str, tuple[str, Any, str]] = {
    "uniform_access_required": ("uniform_bucket_level_access", True, "required"),
    "public_iam_binding_denied": ("public_iam_binding", False, "required"),
    "versioning_recommended": ("versioning_enabled", True, "recommended"),
}

_CONTROL_MAPS: dict[str, dict[str, tuple[str, Any, str]]] = {
    "aws": _AWS_S3_CONTROL_MAP,
    "azure": _AZURE_STORAGE_CONTROL_MAP,
    "gcp": _GCP_GCS_CONTROL_MAP,
}


def load_baseline(baseline_path: str | Path) -> dict[str, Any]:
    """
    Load and parse a YAML baseline file.

    Args:
        baseline_path: Path to the baseline YAML file.

    Returns:
        Dict representation of the baseline.

    Raises:
        FileNotFoundError: If the baseline file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
    """
    path = Path(baseline_path)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    with path.open() as f:
        return yaml.safe_load(f)


def _importance_to_severity(importance: str, deviated: bool) -> str:
    """Derive a severity level from the importance tier and whether drift was detected."""
    if not deviated:
        return "info"  # No deviation
    mapping = {"required": "high", "recommended": "medium", "informational": "low"}
    return mapping.get(importance, "low")


def analyze_drift(
    postures: list[Any],
    provider: str,
    baseline_path: str | Path,
    sensitivity: str = "medium",
    resource_type: str = "storage",
) -> list[DriftItem]:
    """
    Compare live posture objects against a YAML baseline and return drift items.

    Args:
        postures: List of posture dataclass instances from a provider collector.
        provider: Cloud provider identifier ("aws", "azure", "gcp").
        baseline_path: Path to the YAML baseline file.
        sensitivity: Drift sensitivity level ("low", "medium", "high").
        resource_type: Descriptive resource type string for findings.

    Returns:
        List of DriftItem objects representing deviations from the baseline.
    """
    baseline = load_baseline(baseline_path)
    baseline_name = baseline.get("name", Path(baseline_path).stem)

    # Determine which importance levels to include based on sensitivity
    sensitivity_filter: dict[str, set[str]] = {
        "low": {"required"},
        "medium": {"required", "recommended"},
        "high": {"required", "recommended", "informational"},
    }
    include_importance = sensitivity_filter.get(sensitivity, {"required", "recommended"})

    control_map = _CONTROL_MAPS.get(provider, {})
    drift_items: list[DriftItem] = []

    # Extract the storage control expectations from the baseline
    # The baseline YAML structure: storage.<resource_type>.<control_key>: <expected_bool>
    baseline_storage = baseline.get("storage", {})
    baseline_section: dict[str, Any] = {}
    if provider == "aws":
        baseline_section = baseline_storage.get("s3", {})
    elif provider == "azure":
        baseline_section = baseline_storage.get("storage_accounts", {})
    elif provider == "gcp":
        baseline_section = baseline_storage.get("gcs", {})

    for posture in postures:
        resource_name = getattr(posture, "name", "unknown")

        for control_key, (attr, default_expected, importance) in control_map.items():
            if importance not in include_importance:
                continue  # Skip controls below the sensitivity threshold

            # Use the baseline file's value if present, otherwise use the control map default
            expected = baseline_section.get(control_key, default_expected)
            actual = getattr(posture, attr, None)

            if actual is None:
                continue  # Attribute not available; skip

            deviated = actual != expected
            if not deviated:
                continue  # In compliance; no drift item needed

            drift_items.append(DriftItem(
                provider=provider,
                resource_type=resource_type,
                resource_name=resource_name,
                baseline_name=baseline_name,
                control=control_key,
                expected=expected,
                actual=actual,
                importance=importance,
                severity=_importance_to_severity(importance, deviated),
            ))

    # Sort by severity: high deviations first
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    drift_items.sort(key=lambda d: severity_order.get(d.severity, 99))
    return drift_items
