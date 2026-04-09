"""
AWS CloudTrail Logging Gap Analyzer
======================================
Analyzes AWS CloudTrail trail configurations to detect common logging gaps
that reduce security visibility and hamper incident response.

Checks Performed
-----------------
CT-001  Trail disabled
        The trail is not actively logging. All API activity is unrecorded
        during the gap, making forensic investigation impossible.

CT-002  Log file validation disabled
        Log file integrity validation (SHA-256 digest files) is not enabled.
        Without validation, logs can be tampered with undetected.

CT-003  Single-region trail
        The trail is configured to record only one region. API activity in
        other regions (including global services) may be unrecorded.

CT-004  Multi-region global services not included
        The trail does not include global service events (e.g. IAM, STS,
        CloudFront). Privilege escalation and federation attacks via IAM
        are invisible.

CT-005  S3 bucket MFA Delete not required
        The S3 bucket storing trail logs does not require MFA for delete
        operations. An attacker with the bucket credentials can erase logs.

CT-006  S3 bucket not encrypted with KMS
        Trail logs are not encrypted with a customer-managed KMS key.
        Access to logs is not governed by KMS key policies.

CT-007  CloudWatch Logs integration absent
        The trail does not forward logs to CloudWatch Logs. Real-time
        alerting on suspicious activity (e.g. root usage, large-scale
        describe calls) is unavailable.

CT-008  No management events recorded
        The trail is configured to record only data events (e.g. S3 object
        access) but not management (control-plane) events. IAM changes,
        security group modifications, and instance launches are invisible.

Usage::

    from analyzers.cloudtrail_analyzer import (
        TrailPosture,
        CloudTrailAnalyzer,
    )

    analyzer = CloudTrailAnalyzer()
    posture = analyzer.analyze_trail_config(trail_config_dict)
    print(posture.risk_summary())

    # Analyze all trails from boto3 describe_trails() response
    all_postures = analyzer.analyze_trails(trails_list, status_map)
    report = analyzer.build_report(all_postures)
    print(report.summary())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class TrailSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class TrailFinding:
    """
    A single CloudTrail misconfiguration finding.

    Attributes:
        check_id:    Check identifier (CT-001 … CT-008).
        severity:    Finding severity.
        title:       Short description.
        detail:      Detailed explanation.
        remediation: Step to fix the issue.
        trail_name:  Trail ARN or name where the issue was found.
        trail_arn:   Full trail ARN (empty if not known).
    """
    check_id:    str
    severity:    TrailSeverity
    title:       str
    detail:      str
    remediation: str
    trail_name:  str = ""
    trail_arn:   str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "title":       self.title,
            "detail":      self.detail,
            "remediation": self.remediation,
            "trail_name":  self.trail_name,
            "trail_arn":   self.trail_arn,
        }


# ---------------------------------------------------------------------------
# Trail posture
# ---------------------------------------------------------------------------

@dataclass
class TrailPosture:
    """
    Security posture of a single CloudTrail trail.

    Attributes:
        trail_name:  Trail name or ARN.
        trail_arn:   Full trail ARN.
        is_logging:  Whether the trail is actively recording.
        multi_region: Whether the trail captures all regions.
        findings:    List of TrailFindings for this trail.
        risk_score:  Aggregate 0–100 risk score.
    """
    trail_name:   str
    trail_arn:    str = ""
    is_logging:   bool = True
    multi_region: bool = False
    findings:     list[TrailFinding] = field(default_factory=list)
    risk_score:   int = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == TrailSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == TrailSeverity.HIGH)

    def risk_summary(self) -> str:
        return (
            f"Trail '{self.trail_name}' | "
            f"risk={self.risk_score} | "
            f"{self.finding_count} finding(s) "
            f"[CRITICAL={self.critical_count} HIGH={self.high_count}]"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "trail_name":     self.trail_name,
            "trail_arn":      self.trail_arn,
            "is_logging":     self.is_logging,
            "multi_region":   self.multi_region,
            "finding_count":  self.finding_count,
            "risk_score":     self.risk_score,
            "findings":       [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Analysis report
# ---------------------------------------------------------------------------

@dataclass
class CloudTrailReport:
    """
    Aggregated CloudTrail analysis report across all trails.

    Attributes:
        trail_postures:    Per-trail posture results.
        total_trails:      Total trails analyzed.
        trails_disabled:   Number of trails not currently logging.
        all_findings:      Flat list of all findings across all trails.
    """
    trail_postures: list[TrailPosture] = field(default_factory=list)
    total_trails:   int = 0
    trails_disabled: int = 0
    all_findings:   list[TrailFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def critical_findings(self) -> list[TrailFinding]:
        return [f for f in self.all_findings if f.severity == TrailSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[TrailFinding]:
        return [f for f in self.all_findings if f.severity == TrailSeverity.HIGH]

    def summary(self) -> str:
        return (
            f"CloudTrailReport: {self.total_trails} trail(s) | "
            f"{self.trails_disabled} disabled | "
            f"{self.total_findings} finding(s) "
            f"[CRITICAL={len(self.critical_findings)} "
            f"HIGH={len(self.high_findings)}]"
        )

    def findings_by_check(self, check_id: str) -> list[TrailFinding]:
        return [f for f in self.all_findings if f.check_id == check_id]

    def findings_by_severity(self, severity: TrailSeverity) -> list[TrailFinding]:
        return [f for f in self.all_findings if f.severity == severity]


# ---------------------------------------------------------------------------
# CloudTrailAnalyzer
# ---------------------------------------------------------------------------

# Risk score weights per check
_CHECK_WEIGHTS: dict[str, int] = {
    "CT-001": 30,   # Trail disabled — catastrophic visibility loss
    "CT-002": 15,   # No log validation
    "CT-003": 10,   # Single-region
    "CT-004": 10,   # No global service events
    "CT-005": 15,   # No MFA delete on S3
    "CT-006": 5,    # No KMS
    "CT-007": 10,   # No CloudWatch integration
    "CT-008": 20,   # No management events
}

_CHECK_SEVERITIES: dict[str, TrailSeverity] = {
    "CT-001": TrailSeverity.CRITICAL,
    "CT-002": TrailSeverity.HIGH,
    "CT-003": TrailSeverity.MEDIUM,
    "CT-004": TrailSeverity.HIGH,
    "CT-005": TrailSeverity.HIGH,
    "CT-006": TrailSeverity.MEDIUM,
    "CT-007": TrailSeverity.MEDIUM,
    "CT-008": TrailSeverity.CRITICAL,
}


class CloudTrailAnalyzer:
    """
    Analyzes CloudTrail trail configurations for logging gaps.

    Trail config dicts should match the shape returned by boto3
    ``describe_trails(includeShadowTrails=False)["trailList"]``,
    with optional status data from ``get_trail_status()``.

    Expected config keys (snake_case accepted too):
      - TrailARN / trail_arn
      - Name / name
      - IsMultiRegionTrail / is_multi_region_trail
      - IncludeGlobalServiceEvents / include_global_service_events
      - HasCustomEventSelectors / has_custom_event_selectors
      - CloudWatchLogsLogGroupArn / cloud_watch_logs_log_group_arn
      - KMSKeyId / kms_key_id
      - LogFileValidationEnabled / log_file_validation_enabled
      - S3BucketName / s3_bucket_name

    Optional status keys:
      - IsLogging / is_logging
      - HasCustomEventSelectors / has_custom_event_selectors

    Optional S3 bucket metadata keys (for MFA delete check):
      - S3MfaDeleteEnabled / s3_mfa_delete_enabled
    """

    def analyze_trail_config(
        self,
        config: dict[str, Any],
        status: Optional[dict[str, Any]] = None,
    ) -> TrailPosture:
        """
        Analyze a single trail configuration dict.

        Args:
            config: Trail configuration dict from describe_trails().
            status: Trail status dict from get_trail_status() (optional).

        Returns a TrailPosture with all findings.
        """
        status = status or {}

        trail_name = _get(config, "Name", "name", "TrailName", default="unknown")
        trail_arn  = _get(config, "TrailARN", "trail_arn", default="")
        is_logging = bool(_get(status or config, "IsLogging", "is_logging", default=True))
        multi_region = bool(_get(config, "IsMultiRegionTrail", "is_multi_region_trail", default=False))

        posture = TrailPosture(
            trail_name=trail_name,
            trail_arn=trail_arn,
            is_logging=is_logging,
            multi_region=multi_region,
        )

        findings: list[TrailFinding] = []

        # CT-001: Trail disabled
        if not is_logging:
            findings.append(TrailFinding(
                check_id="CT-001",
                severity=TrailSeverity.CRITICAL,
                title="CloudTrail trail is not logging",
                detail=(
                    f"Trail '{trail_name}' has logging disabled. "
                    "All API activity is unrecorded, making forensic "
                    "investigation and threat detection impossible."
                ),
                remediation=(
                    "Enable the trail: `aws cloudtrail start-logging "
                    "--name <trail-name>`"
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        # CT-002: Log file validation disabled
        if not bool(_get(config, "LogFileValidationEnabled", "log_file_validation_enabled",
                         default=False)):
            findings.append(TrailFinding(
                check_id="CT-002",
                severity=TrailSeverity.HIGH,
                title="Log file validation disabled",
                detail=(
                    "CloudTrail log file integrity validation is not enabled. "
                    "Without SHA-256 digest files, log tampering cannot be "
                    "detected after the fact."
                ),
                remediation=(
                    "Enable validation: `aws cloudtrail update-trail "
                    "--name <trail-name> --enable-log-file-validation`"
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        # CT-003: Single-region trail
        if not multi_region:
            findings.append(TrailFinding(
                check_id="CT-003",
                severity=TrailSeverity.MEDIUM,
                title="Single-region trail — other regions unmonitored",
                detail=(
                    f"Trail '{trail_name}' records activity in one region only. "
                    "An attacker operating in other regions (e.g. us-west-2 when "
                    "this trail covers us-east-1) will be invisible."
                ),
                remediation=(
                    "Convert to multi-region: `aws cloudtrail update-trail "
                    "--name <trail-name> --is-multi-region-trail`"
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        # CT-004: Global service events missing (only check for multi-region trails
        #         or explicitly configured single-region trails)
        includes_global = bool(_get(
            config, "IncludeGlobalServiceEvents", "include_global_service_events",
            default=True
        ))
        if not includes_global:
            findings.append(TrailFinding(
                check_id="CT-004",
                severity=TrailSeverity.HIGH,
                title="Global service events not included",
                detail=(
                    "IAM, STS, and CloudFront events are not captured by this trail. "
                    "Privilege escalation and credential abuse via IAM are invisible."
                ),
                remediation=(
                    "Enable global events: `aws cloudtrail update-trail "
                    "--name <trail-name> --include-global-service-events`"
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        # CT-005: S3 MFA delete not required
        mfa_delete_enabled = _get(
            config, "S3MfaDeleteEnabled", "s3_mfa_delete_enabled", default=None
        )
        if mfa_delete_enabled is False:
            findings.append(TrailFinding(
                check_id="CT-005",
                severity=TrailSeverity.HIGH,
                title="MFA delete not required on trail log bucket",
                detail=(
                    f"The S3 bucket storing trail logs does not require MFA for "
                    "delete operations. An attacker with bucket credentials can "
                    "delete log files without a second factor."
                ),
                remediation=(
                    "Enable MFA delete on the S3 bucket: "
                    "`aws s3api put-bucket-versioning --bucket <bucket> "
                    "--versioning-configuration Status=Enabled,MFADelete=Enabled "
                    "--mfa <device-serial> <code>`"
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        # CT-006: No KMS encryption
        kms_key = _get(config, "KMSKeyId", "kms_key_id", default=None)
        if not kms_key:
            findings.append(TrailFinding(
                check_id="CT-006",
                severity=TrailSeverity.MEDIUM,
                title="Trail logs not encrypted with KMS",
                detail=(
                    "CloudTrail logs are stored in S3 with default encryption "
                    "only, not with a customer-managed KMS key. Access to logs "
                    "cannot be controlled via KMS key policies."
                ),
                remediation=(
                    "Configure KMS: `aws cloudtrail update-trail "
                    "--name <trail-name> --kms-key-id <key-arn>`"
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        # CT-007: No CloudWatch Logs integration
        cw_group = _get(
            config, "CloudWatchLogsLogGroupArn", "cloud_watch_logs_log_group_arn",
            default=None
        )
        if not cw_group:
            findings.append(TrailFinding(
                check_id="CT-007",
                severity=TrailSeverity.MEDIUM,
                title="CloudWatch Logs integration absent",
                detail=(
                    "Trail logs are not forwarded to CloudWatch Logs. "
                    "Real-time metric filters and alarms for suspicious activity "
                    "(root usage, IAM changes, console failures) are not available."
                ),
                remediation=(
                    "Configure CloudWatch integration in the trail settings and "
                    "create metric filters for CIS Benchmark CloudWatch alarms."
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        # CT-008: No management events
        # Custom event selectors can exclude management events.
        # If has_custom_event_selectors is True but event_selectors (from
        # get_event_selectors) shows no ReadWriteType or excludes management,
        # flag it. Without detailed event selectors, check the combined flag.
        management_events = bool(_get(
            config, "ManagementEventsEnabled", "management_events_enabled",
            default=True  # default: assume enabled unless told otherwise
        ))
        if not management_events:
            findings.append(TrailFinding(
                check_id="CT-008",
                severity=TrailSeverity.CRITICAL,
                title="Management (control-plane) events not recorded",
                detail=(
                    "The trail is configured to exclude management events. "
                    "IAM changes, security group modifications, key pair creation, "
                    "and instance launches are not logged."
                ),
                remediation=(
                    "Update event selectors to include management events: "
                    "`aws cloudtrail put-event-selectors --trail-name <name> "
                    "--event-selectors '[{\"ReadWriteType\": \"All\", "
                    "\"IncludeManagementEvents\": true}]'`"
                ),
                trail_name=trail_name,
                trail_arn=trail_arn,
            ))

        posture.findings = findings
        posture.risk_score = min(100, sum(
            _CHECK_WEIGHTS.get(f.check_id, 5) for f in findings
        ))

        return posture

    def analyze_trails(
        self,
        trails: list[dict[str, Any]],
        status_map: Optional[dict[str, dict[str, Any]]] = None,
    ) -> list[TrailPosture]:
        """
        Analyze multiple trails.

        Args:
            trails:     List of trail config dicts.
            status_map: Optional dict of trail_name → status dict.

        Returns a list of TrailPosture objects.
        """
        status_map = status_map or {}
        postures = []
        for trail in trails:
            name   = _get(trail, "Name", "name", default="")
            status = status_map.get(name, {})
            postures.append(self.analyze_trail_config(trail, status))
        return postures

    def build_report(self, postures: list[TrailPosture]) -> CloudTrailReport:
        """Build an aggregated CloudTrailReport from a list of postures."""
        all_findings: list[TrailFinding] = []
        disabled = 0
        for p in postures:
            all_findings.extend(p.findings)
            if not p.is_logging:
                disabled += 1
        return CloudTrailReport(
            trail_postures=postures,
            total_trails=len(postures),
            trails_disabled=disabled,
            all_findings=all_findings,
        )


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _get(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return default
