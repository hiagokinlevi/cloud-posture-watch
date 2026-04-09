"""
Posture Schemas
================
Pydantic models for the canonical data structures used across
cloud-posture-watch.

These models are used for:
  - Serialising findings to JSON (for CI integrations and downstream tools)
  - Validating baseline profiles when they are loaded
  - Typing the report generation layer

All models use Pydantic v2 conventions (model_config, field validators).
"""
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


class Provider(str, Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Importance(str, Enum):
    """Baseline control importance levels."""
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    INFORMATIONAL = "informational"


class ResourcePosture(BaseModel):
    """
    Canonical representation of a single cloud resource's posture.

    Populated by provider collectors and consumed by analyzers and reports.
    """
    provider: Provider
    resource_type: str = Field(..., description="e.g. 's3_bucket', 'storage_account', 'gcs_bucket'")
    resource_name: str
    region: Optional[str] = None
    risk_flags: list[str] = Field(default_factory=list)
    raw_attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider-specific attributes for detailed analysis",
    )
    assessed_at: datetime = Field(default_factory=datetime.utcnow)


class PostureFinding(BaseModel):
    """
    A single security finding derived from posture analysis.

    Produced by the exposure, logging, and drift analyzers.
    """
    provider: Provider
    resource_type: str
    resource_name: str
    severity: Severity
    flag: str = Field(..., description="Machine-readable flag identifier")
    title: str = Field(..., description="Short human-readable description")
    recommendation: str = Field(..., description="Actionable remediation guidance")
    # Optional: link to a specific baseline control that was violated
    baseline_name: Optional[str] = None
    baseline_control: Optional[str] = None

    @model_validator(mode="after")
    def validate_severity_flag_presence(self) -> "PostureFinding":
        """Ensure that critical findings always have a non-empty recommendation."""
        if self.severity == Severity.CRITICAL and not self.recommendation.strip():
            raise ValueError("Critical findings must include a recommendation.")
        return self


class DriftItem(BaseModel):
    """
    A single configuration drift item: one resource attribute that deviates
    from the expected baseline value.
    """
    provider: Provider
    resource_type: str
    resource_name: str
    baseline_name: str
    control: str
    expected: Any
    actual: Any
    importance: Importance
    severity: Severity


class PostureReport(BaseModel):
    """
    Top-level report container holding all findings for a single assessment run.
    """
    run_id: str
    provider: Provider
    baseline_name: Optional[str] = None
    assessed_at: datetime = Field(default_factory=datetime.utcnow)
    total_resources: int = 0
    findings: list[PostureFinding] = Field(default_factory=list)
    drift_items: list[DriftItem] = Field(default_factory=list)

    @property
    def finding_counts(self) -> dict[str, int]:
        """Return a breakdown of findings by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def has_high_or_critical(self) -> bool:
        """Return True if any finding is HIGH or CRITICAL severity."""
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )
