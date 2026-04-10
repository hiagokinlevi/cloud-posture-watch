"""
Offline AWS Secrets Manager and SSM Parameter Store posture analyzer.

Correlates approved managed-secret inventory exports with approved
hardcoded-credential findings so teams can spot where code still embeds
credentials that should already be sourced from AWS managed secret stores.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


_CREDENTIAL_KEYWORDS = {
    "access",
    "apikey",
    "api",
    "auth",
    "credential",
    "db",
    "key",
    "pass",
    "password",
    "private",
    "secret",
    "token",
}
_TOKEN_STOPWORDS = {
    "app",
    "application",
    "aws",
    "config",
    "cred",
    "credentials",
    "manager",
    "param",
    "parameter",
    "prod",
    "production",
    "service",
    "shared",
    "ssm",
    "stage",
    "staging",
    "store",
    "string",
    "value",
}
_CHECK_WEIGHTS = {
    "AWS-SEC-001": 40,
    "AWS-SEC-002": 35,
    "AWS-SEC-003": 20,
}


class AWSSecretsSeverity(str, Enum):
    """Severity levels for AWS secrets posture findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AWSManagedSecret:
    """Normalized managed secret or parameter-store evidence."""

    name: str
    store_type: str
    secure: bool = True
    rotation_enabled: bool | None = None
    kms_key_id: str = ""

    @property
    def resource_type(self) -> str:
        return "secrets_manager_secret" if self.store_type == "secrets_manager" else "ssm_parameter"

    @property
    def normalized_name(self) -> str:
        return self.name.strip().lower().strip("/")

    @property
    def tokens(self) -> set[str]:
        return _tokenize(self.name)

    @property
    def is_credential_like(self) -> bool:
        return bool(self.tokens & _CREDENTIAL_KEYWORDS)

    @classmethod
    def from_secret_dict(cls, data: dict[str, Any]) -> "AWSManagedSecret":
        return cls(
            name=str(data.get("Name") or data.get("name") or "unknown-secret"),
            store_type="secrets_manager",
            secure=True,
            rotation_enabled=_coerce_optional_bool(
                data.get("RotationEnabled")
                if "RotationEnabled" in data
                else data.get("rotation_enabled")
            ),
            kms_key_id=str(data.get("KmsKeyId") or data.get("kms_key_id") or ""),
        )

    @classmethod
    def from_parameter_dict(cls, data: dict[str, Any]) -> "AWSManagedSecret":
        parameter_type = str(data.get("Type") or data.get("type") or "")
        return cls(
            name=str(data.get("Name") or data.get("name") or "unknown-parameter"),
            store_type="ssm_parameter",
            secure=parameter_type.lower() == "securestring",
            kms_key_id=str(data.get("KeyId") or data.get("key_id") or ""),
        )


@dataclass
class HardcodedCredentialEvidence:
    """Normalized hardcoded-credential finding evidence."""

    source_path: str
    category: str = "credential"
    identifier: str = ""
    managed_hint: str = ""

    @property
    def resource_name(self) -> str:
        return self.source_path or self.identifier or "unknown-source"

    @property
    def normalized_hint(self) -> str:
        return self.managed_hint.strip().lower().strip("/")

    @property
    def tokens(self) -> set[str]:
        tokens = set()
        if self.identifier:
            tokens |= _tokenize(self.identifier)
        if self.managed_hint:
            tokens |= _tokenize(self.managed_hint)
        if self.source_path:
            tokens |= _tokenize(Path(self.source_path).stem)
        return tokens

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HardcodedCredentialEvidence":
        return cls(
            source_path=str(
                data.get("path")
                or data.get("file")
                or data.get("source_path")
                or data.get("source")
                or "unknown-file"
            ),
            category=str(
                data.get("category")
                or data.get("detector")
                or data.get("kind")
                or data.get("type")
                or "credential"
            ).strip().lower(),
            identifier=str(
                data.get("identifier")
                or data.get("name")
                or data.get("variable")
                or data.get("secret_name")
                or data.get("title")
                or ""
            ),
            managed_hint=str(
                data.get("managed_hint")
                or data.get("managed_secret")
                or data.get("parameter_name")
                or data.get("secret_id")
                or ""
            ),
        )


@dataclass
class AWSSecretsFinding:
    """A single AWS secrets posture finding."""

    check_id: str
    severity: AWSSecretsSeverity
    resource_type: str
    resource_name: str
    title: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class AWSSecretsReport:
    """Aggregated AWS secrets analyzer result."""

    findings: list[AWSSecretsFinding] = field(default_factory=list)
    managed_entries_analyzed: int = 0
    hardcoded_evidence_analyzed: int = 0
    risk_score: int = 0
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def findings_by_check(self, check_id: str) -> list[AWSSecretsFinding]:
        return [finding for finding in self.findings if finding.check_id == check_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "managed_entries_analyzed": self.managed_entries_analyzed,
            "hardcoded_evidence_analyzed": self.hardcoded_evidence_analyzed,
            "generated_at": self.generated_at,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class AWSSecretsAnalyzer:
    """Correlate managed AWS secret inventory with hardcoded credential evidence."""

    def analyze(
        self,
        managed_entries: list[AWSManagedSecret],
        hardcoded_evidence: list[HardcodedCredentialEvidence],
    ) -> AWSSecretsReport:
        findings: list[AWSSecretsFinding] = []
        for evidence in hardcoded_evidence:
            managed_match = self._find_managed_match(evidence, managed_entries)
            if managed_match is not None:
                findings.append(self._build_duplicate_finding(evidence, managed_match))
            else:
                findings.append(self._build_unmanaged_finding(evidence))

        for entry in managed_entries:
            if entry.store_type != "ssm_parameter" or entry.secure or not entry.is_credential_like:
                continue
            findings.append(
                AWSSecretsFinding(
                    check_id="AWS-SEC-003",
                    severity=AWSSecretsSeverity.MEDIUM,
                    resource_type=entry.resource_type,
                    resource_name=entry.name,
                    title="Credential-like SSM parameter is stored as plaintext",
                    detail=(
                        f"SSM parameter '{entry.name}' looks credential-related based on its name, "
                        "but the export shows it is stored as `String` instead of `SecureString`."
                    ),
                    recommendation=(
                        "Store credential-bearing parameters as `SecureString` with a customer-managed "
                        "KMS key or migrate them to AWS Secrets Manager when rotation or richer access "
                        "control is needed."
                    ),
                )
            )

        fired_checks = {finding.check_id for finding in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(check_id, 10) for check_id in fired_checks))
        return AWSSecretsReport(
            findings=findings,
            managed_entries_analyzed=len(managed_entries),
            hardcoded_evidence_analyzed=len(hardcoded_evidence),
            risk_score=risk_score,
        )

    def _find_managed_match(
        self,
        evidence: HardcodedCredentialEvidence,
        managed_entries: list[AWSManagedSecret],
    ) -> AWSManagedSecret | None:
        if evidence.normalized_hint:
            for entry in managed_entries:
                if entry.normalized_name == evidence.normalized_hint:
                    return entry

        evidence_tokens = evidence.tokens
        if not evidence_tokens:
            return None

        best_match: AWSManagedSecret | None = None
        best_score = 0
        for entry in managed_entries:
            shared = evidence_tokens & entry.tokens
            if not shared:
                continue
            score = len(shared)
            if entry.is_credential_like:
                score += 1
            if evidence.identifier and evidence.identifier.lower().replace("_", "-") in entry.normalized_name:
                score += 1
            if score > best_score and (
                len(shared) >= 2 or shared & _CREDENTIAL_KEYWORDS
            ):
                best_match = entry
                best_score = score
        return best_match

    def _build_duplicate_finding(
        self,
        evidence: HardcodedCredentialEvidence,
        entry: AWSManagedSecret,
    ) -> AWSSecretsFinding:
        source_label = evidence.identifier or evidence.category or "credential"
        return AWSSecretsFinding(
            check_id="AWS-SEC-001",
            severity=_severity_for_category(evidence.category),
            resource_type=entry.resource_type,
            resource_name=entry.name,
            title="Hardcoded credential appears to duplicate an AWS managed secret",
            detail=(
                f"Hardcoded credential evidence from '{evidence.resource_name}' overlaps with managed "
                f"{'Secrets Manager secret' if entry.store_type == 'secrets_manager' else 'SSM parameter'} "
                f"'{entry.name}'. This suggests application code may still embed {source_label} values "
                "instead of resolving them from AWS-managed secret storage."
            ),
            recommendation=(
                "Remove inline credential literals from code and configuration, read the value at runtime "
                "from the matched AWS managed secret, and rotate the exposed credential after migration."
            ),
        )

    def _build_unmanaged_finding(self, evidence: HardcodedCredentialEvidence) -> AWSSecretsFinding:
        return AWSSecretsFinding(
            check_id="AWS-SEC-002",
            severity=_severity_for_category(evidence.category),
            resource_type="hardcoded_credential",
            resource_name=evidence.resource_name,
            title="Hardcoded credential lacks an AWS managed secret counterpart",
            detail=(
                f"Approved hardcoded credential evidence was supplied for '{evidence.resource_name}', "
                "but no matching AWS Secrets Manager secret or SSM parameter was found in the inventory "
                "export. This increases rotation friction and keeps sensitive material embedded in code or "
                "configuration."
            ),
            recommendation=(
                "Move the credential into AWS Secrets Manager or a `SecureString` SSM parameter, update "
                "the workload to read it at runtime, and rotate any literal that was committed or deployed."
            ),
        )


def load_aws_secrets_from_export(
    path: str | Path,
) -> tuple[list[AWSManagedSecret], list[HardcodedCredentialEvidence]]:
    """Load managed-secret inventory and hardcoded-credential evidence from JSON."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_aws_secrets_from_export_dict(payload)


def load_aws_secrets_from_export_dict(
    payload: Any,
) -> tuple[list[AWSManagedSecret], list[HardcodedCredentialEvidence]]:
    """Normalize common AWS secrets export shapes."""
    if isinstance(payload, list):
        return (
            [AWSManagedSecret.from_secret_dict(item) for item in payload if isinstance(item, dict)],
            [],
        )
    if not isinstance(payload, dict):
        return [], []

    managed_entries: list[AWSManagedSecret] = []
    for item in _extract_list(payload, ("secrets", "SecretList", "secret_list")):
        if isinstance(item, dict):
            managed_entries.append(AWSManagedSecret.from_secret_dict(item))
    for item in _extract_list(payload, ("parameters", "Parameters", "parameter_list")):
        if isinstance(item, dict):
            managed_entries.append(AWSManagedSecret.from_parameter_dict(item))

    hardcoded_evidence = [
        HardcodedCredentialEvidence.from_dict(item)
        for item in _extract_list(
            payload,
            ("hardcoded_credentials", "hardcodedCredentials", "code_findings", "findings"),
        )
        if isinstance(item, dict)
    ]
    return managed_entries, hardcoded_evidence


def _extract_list(payload: Any, keys: tuple[str, ...]) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    for key in ("results", "data", "value"):
        value = payload.get(key)
        if isinstance(value, dict):
            extracted = _extract_list(value, keys)
            if extracted:
                return extracted
    return []


def _coerce_optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "enabled", "on"}:
        return True
    if normalized in {"false", "0", "no", "disabled", "off"}:
        return False
    return None


def _severity_for_category(category: str) -> AWSSecretsSeverity:
    normalized = category.strip().lower()
    if any(token in normalized for token in ("access_key", "access-key", "private", "pem", "ssh")):
        return AWSSecretsSeverity.CRITICAL
    if any(token in normalized for token in ("token", "password", "secret", "connection")):
        return AWSSecretsSeverity.HIGH
    return AWSSecretsSeverity.MEDIUM


def _tokenize(value: str) -> set[str]:
    tokens = set()
    for token in re.split(r"[^a-z0-9]+", value.lower()):
        if len(token) < 2 or token in _TOKEN_STOPWORDS:
            continue
        if token == "apikey":
            tokens.update({"api", "key"})
            continue
        tokens.add(token)
    return tokens
