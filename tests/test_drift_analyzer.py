"""
Tests for analyzers/drift_analyzer.py
=======================================
Validates that the drift analyzer correctly compares posture objects
against YAML baselines and produces accurate drift items.
"""
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml

from analyzers.drift_analyzer import DriftItem, analyze_drift, load_baseline


@dataclass
class MockBucketPosture:
    """Mock S3 bucket posture for testing the drift analyzer."""
    name: str
    public_access_blocked: bool = True
    encryption_enabled: bool = True
    logging_enabled: bool = True
    versioning_enabled: bool = False   # Default: off (required by recommended control)
    risk_flags: list[str] = field(default_factory=list)


def _write_temp_baseline(content: dict) -> Path:
    """Write a YAML baseline to a temporary file and return its path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    yaml.dump(content, tmp)
    tmp.close()
    return Path(tmp.name)


MINIMAL_BASELINE = {
    "name": "test_baseline",
    "version": "1.0",
    "provider": "aws",
    "profile": "test",
    "storage": {
        "s3": {
            "public_access_block_required": True,
            "encryption_required": True,
            "logging_required": True,
            "versioning_recommended": True,
        }
    },
}


class TestLoadBaseline:
    """Tests for load_baseline()."""

    def test_loads_valid_yaml(self):
        path = _write_temp_baseline(MINIMAL_BASELINE)
        baseline = load_baseline(path)
        assert baseline["name"] == "test_baseline"
        assert baseline["provider"] == "aws"

    def test_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_baseline("/nonexistent/path/baseline.yaml")


class TestAnalyzeDrift:
    """Tests for analyze_drift()."""

    def test_no_drift_when_compliant(self):
        """A fully compliant bucket should produce no drift items."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        postures = [
            MockBucketPosture(
                name="good-bucket",
                public_access_blocked=True,
                encryption_enabled=True,
                logging_enabled=True,
                versioning_enabled=True,  # Matches recommended=True
            )
        ]
        drift = analyze_drift(postures, provider="aws", baseline_path=baseline_path)
        assert drift == []

    def test_required_control_violation_produces_high_severity(self):
        """A required control set to False in posture should produce a HIGH drift item."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        postures = [
            MockBucketPosture(
                name="no-encryption",
                encryption_enabled=False,  # Violates encryption_required
            )
        ]
        drift = analyze_drift(postures, provider="aws", baseline_path=baseline_path, sensitivity="medium")
        encryption_drift = [d for d in drift if d.control == "encryption_required"]
        assert len(encryption_drift) == 1
        assert encryption_drift[0].severity == "high"
        assert encryption_drift[0].actual is False
        assert encryption_drift[0].expected is True

    def test_recommended_control_violation_produces_medium_severity(self):
        """A recommended control deviation should produce a MEDIUM drift item."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        postures = [
            MockBucketPosture(
                name="no-versioning",
                versioning_enabled=False,  # Violates versioning_recommended
            )
        ]
        drift = analyze_drift(postures, provider="aws", baseline_path=baseline_path, sensitivity="medium")
        versioning_drift = [d for d in drift if d.control == "versioning_recommended"]
        assert len(versioning_drift) == 1
        assert versioning_drift[0].severity == "medium"

    def test_low_sensitivity_skips_recommended_controls(self):
        """At sensitivity=low, only required controls should be checked."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        postures = [
            MockBucketPosture(
                name="no-versioning",
                versioning_enabled=False,  # recommended, not required
            )
        ]
        drift = analyze_drift(postures, provider="aws", baseline_path=baseline_path, sensitivity="low")
        # versioning_recommended should be skipped at low sensitivity
        versioning_drift = [d for d in drift if d.control == "versioning_recommended"]
        assert versioning_drift == []

    def test_drift_sorted_high_first(self):
        """Drift items should be sorted by severity with high severity first."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        postures = [
            MockBucketPosture(
                name="multi-drift",
                encryption_enabled=False,   # required -> high
                versioning_enabled=False,   # recommended -> medium
            )
        ]
        drift = analyze_drift(postures, provider="aws", baseline_path=baseline_path, sensitivity="medium")
        assert drift[0].severity == "high"

    def test_multiple_buckets_each_produce_drift(self):
        """Each non-compliant bucket should have its own drift items."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        postures = [
            MockBucketPosture(name="bucket-a", encryption_enabled=False),
            MockBucketPosture(name="bucket-b", logging_enabled=False),
        ]
        drift = analyze_drift(postures, provider="aws", baseline_path=baseline_path, sensitivity="low")
        resource_names = {d.resource_name for d in drift}
        assert "bucket-a" in resource_names
        assert "bucket-b" in resource_names

    def test_baseline_name_propagated_to_drift_item(self):
        """The baseline name should be propagated to all drift items."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        postures = [MockBucketPosture(name="b", encryption_enabled=False)]
        drift = analyze_drift(postures, provider="aws", baseline_path=baseline_path)
        assert all(d.baseline_name == "test_baseline" for d in drift)

    def test_empty_posture_list_returns_empty_drift(self):
        """An empty posture list should return no drift items."""
        baseline_path = _write_temp_baseline(MINIMAL_BASELINE)
        drift = analyze_drift([], provider="aws", baseline_path=baseline_path)
        assert drift == []
