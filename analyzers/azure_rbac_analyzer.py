"""
Offline Azure RBAC posture analyzer.

Reviews Azure role assignment exports for broad standing access and guest or
service-principal privilege risk without requiring live Azure credentials.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class AzureRBACSeverity(str, Enum):
    """Severity levels for Azure RBAC findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AzureRolePermission:
    """Permission set from an Azure custom role definition."""

    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    data_actions: list[str] = field(default_factory=list)
    not_data_actions: list[str] = field(default_factory=list)


@dataclass
class AzureRoleAssignment:
    """Normalized Azure role assignment evidence."""

    scope: str
    role_name: str
    principal_name: str = "unknown"
    principal_type: str = "unknown"
    principal_id: str = "unknown"
    assignment_id: str = "unknown"
    role_definition_id: str = ""
    condition: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AzureRoleAssignment":
        """Build an assignment from Azure CLI or Resource Graph JSON."""
        properties = data.get("properties") if isinstance(data.get("properties"), dict) else {}
        role_name = (
            data.get("roleDefinitionName")
            or data.get("role_name")
            or data.get("roleName")
            or properties.get("roleDefinitionName")
            or data.get("role")
            or "unknown"
        )
        principal_name = (
            data.get("principalName")
            or data.get("principal_name")
            or data.get("principalDisplayName")
            or data.get("signInName")
            or properties.get("principalName")
            or properties.get("principalDisplayName")
            or "unknown"
        )
        principal_type = (
            data.get("principalType")
            or data.get("principal_type")
            or properties.get("principalType")
            or "unknown"
        )
        role_definition_id = (
            data.get("roleDefinitionId")
            or data.get("role_definition_id")
            or properties.get("roleDefinitionId")
            or ""
        )
        return cls(
            scope=str(data.get("scope") or properties.get("scope") or "unknown"),
            role_name=str(role_name),
            principal_name=str(principal_name),
            principal_type=str(principal_type),
            principal_id=str(
                data.get("principalId")
                or data.get("principal_id")
                or properties.get("principalId")
                or principal_name
                or "unknown"
            ),
            assignment_id=str(data.get("id") or data.get("assignment_id") or data.get("name") or "unknown"),
            role_definition_id=str(role_definition_id),
            condition=_optional_str(data.get("condition") or properties.get("condition")),
        )


@dataclass
class AzureRoleDefinition:
    """Normalized Azure role definition evidence."""

    name: str
    role_id: str = ""
    is_custom: bool = False
    permissions: list[AzureRolePermission] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AzureRoleDefinition":
        """Build a role definition from Azure CLI or Resource Graph JSON."""
        properties = data.get("properties") if isinstance(data.get("properties"), dict) else {}
        name = data.get("roleName") or data.get("role_name") or properties.get("roleName") or data.get("name") or ""
        role_id = (
            data.get("id")
            or data.get("roleDefinitionId")
            or data.get("role_definition_id")
            or properties.get("id")
            or properties.get("roleDefinitionId")
            or data.get("name")
            or ""
        )
        raw_permissions = data.get("permissions") or properties.get("permissions") or []
        permissions = [
            AzureRolePermission(
                actions=_as_str_list(item.get("actions") or item.get("Actions") or []),
                not_actions=_as_str_list(item.get("notActions") or item.get("not_actions") or []),
                data_actions=_as_str_list(item.get("dataActions") or item.get("data_actions") or []),
                not_data_actions=_as_str_list(item.get("notDataActions") or item.get("not_data_actions") or []),
            )
            for item in raw_permissions
            if isinstance(item, dict)
        ]
        role_type = str(data.get("type") or properties.get("type") or data.get("roleType") or "")
        return cls(
            name=str(name),
            role_id=str(role_id),
            is_custom=_truthy(data.get("isCustom") or data.get("is_custom") or properties.get("isCustom"))
            or role_type.lower() == "customrole",
            permissions=permissions,
        )


@dataclass
class AzureRBACFinding:
    """A single Azure RBAC posture finding."""

    check_id: str
    severity: AzureRBACSeverity
    scope: str
    principal: str
    role: str
    title: str
    detail: str
    recommendation: str

    @property
    def resource_type(self) -> str:
        return "role_assignment"

    @property
    def resource_name(self) -> str:
        return f"{self.scope}:{self.principal}:{self.role}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a JSON-friendly dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "scope": self.scope,
            "principal": self.principal,
            "role": self.role,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class AzureRBACReport:
    """Aggregated Azure RBAC analyzer result."""

    findings: list[AzureRBACFinding] = field(default_factory=list)
    assignments_analyzed: int = 0
    role_definitions_analyzed: int = 0
    risk_score: int = 0
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[AzureRBACFinding]:
        return [f for f in self.findings if f.severity == AzureRBACSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[AzureRBACFinding]:
        return [f for f in self.findings if f.severity == AzureRBACSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> list[AzureRBACFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "critical": len(self.critical_findings),
            "high": len(self.high_findings),
            "assignments_analyzed": self.assignments_analyzed,
            "role_definitions_analyzed": self.role_definitions_analyzed,
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
        }


_OWNER_ROLES = {"owner"}
_CONTRIBUTOR_ROLES = {"contributor"}
_PRIVILEGED_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "privileged role administrator",
}
_CHECK_WEIGHTS = {
    "AZ-RBAC-001": 50,
    "AZ-RBAC-002": 35,
    "AZ-RBAC-003": 45,
    "AZ-RBAC-004": 35,
    "AZ-RBAC-005": 40,
    "AZ-RBAC-006": 35,
}


class AzureRBACAnalyzer:
    """Analyze offline Azure RBAC assignments and custom role definitions."""

    def __init__(
        self,
        trusted_domains: list[str] | None = None,
        check_external_principals: bool = True,
    ) -> None:
        self._trusted_domains = [d.lower() for d in trusted_domains or []]
        self._check_external_principals = check_external_principals

    def analyze(
        self,
        assignments: list[AzureRoleAssignment],
        role_definitions: list[AzureRoleDefinition] | None = None,
    ) -> AzureRBACReport:
        role_definitions = role_definitions or []
        role_map = _role_definition_map(role_definitions)
        findings: list[AzureRBACFinding] = []
        for assignment in assignments:
            findings.extend(self._check_broad_builtin_assignment(assignment))
            findings.extend(self._check_guest_or_external_principal(assignment))
            findings.extend(self._check_service_principal_owner(assignment))
            findings.extend(self._check_privileged_role_assignment(assignment))
            definition = _definition_for_assignment(assignment, role_map)
            if definition:
                findings.extend(self._check_custom_role_wildcard(assignment, definition))

        fired_checks = {finding.check_id for finding in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(check_id, 10) for check_id in fired_checks))
        return AzureRBACReport(
            findings=findings,
            assignments_analyzed=len(assignments),
            role_definitions_analyzed=len(role_definitions),
            risk_score=risk_score,
        )

    def _check_broad_builtin_assignment(
        self,
        assignment: AzureRoleAssignment,
    ) -> list[AzureRBACFinding]:
        normalized_role = _normalize_role_name(assignment.role_name)
        if not _is_broad_scope(assignment.scope):
            return []
        if normalized_role in _OWNER_ROLES:
            return [
                AzureRBACFinding(
                    check_id="AZ-RBAC-001",
                    severity=AzureRBACSeverity.CRITICAL,
                    scope=assignment.scope,
                    principal=assignment.principal_name,
                    role=assignment.role_name,
                    title="Owner role assigned at broad Azure scope",
                    detail=(
                        f"Principal '{assignment.principal_name}' has Owner on "
                        f"'{assignment.scope}', granting full control and role "
                        "assignment capability across a subscription or management group."
                    ),
                    recommendation=(
                        "Replace standing Owner with narrowly scoped roles. Use PIM "
                        "eligible activation and restrict assignment scope to the "
                        "smallest resource group or resource possible."
                    ),
                )
            ]
        if normalized_role in _CONTRIBUTOR_ROLES:
            return [
                AzureRBACFinding(
                    check_id="AZ-RBAC-002",
                    severity=AzureRBACSeverity.HIGH,
                    scope=assignment.scope,
                    principal=assignment.principal_name,
                    role=assignment.role_name,
                    title="Contributor role assigned at broad Azure scope",
                    detail=(
                        f"Principal '{assignment.principal_name}' has Contributor on "
                        f"'{assignment.scope}'. Contributor can modify most resources "
                        "and should rarely be standing access at subscription or "
                        "management-group scope."
                    ),
                    recommendation=(
                        "Split Contributor into service-specific least-privilege roles "
                        "and scope access to required resource groups or resources."
                    ),
                )
            ]
        return []

    def _check_guest_or_external_principal(
        self,
        assignment: AzureRoleAssignment,
    ) -> list[AzureRBACFinding]:
        if not self._check_external_principals:
            return []
        if _normalize_role_name(assignment.role_name) not in _PRIVILEGED_ROLES:
            return []
        if not (_is_guest_principal(assignment) or self._is_untrusted_user(assignment.principal_name)):
            return []
        return [
            AzureRBACFinding(
                check_id="AZ-RBAC-003",
                severity=AzureRBACSeverity.CRITICAL,
                scope=assignment.scope,
                principal=assignment.principal_name,
                role=assignment.role_name,
                title="Guest or external principal holds privileged Azure RBAC role",
                detail=(
                    f"External principal '{assignment.principal_name}' has "
                    f"'{assignment.role_name}' on '{assignment.scope}', expanding "
                    "the blast radius outside the trusted tenant boundary."
                ),
                recommendation=(
                    "Remove guest and external principals from privileged role "
                    "assignments. Use time-bound access packages or PIM-reviewed "
                    "guest access when cross-tenant administration is required."
                ),
            )
        ]

    def _check_service_principal_owner(
        self,
        assignment: AzureRoleAssignment,
    ) -> list[AzureRBACFinding]:
        if _normalize_role_name(assignment.role_name) != "owner":
            return []
        if assignment.principal_type.lower() not in {"serviceprincipal", "application"}:
            return []
        return [
            AzureRBACFinding(
                check_id="AZ-RBAC-004",
                severity=AzureRBACSeverity.HIGH,
                scope=assignment.scope,
                principal=assignment.principal_name,
                role=assignment.role_name,
                title="Service principal assigned Owner",
                detail=(
                    f"Service principal '{assignment.principal_name}' has Owner on "
                    f"'{assignment.scope}'. Compromise of its secret or federated "
                    "credential would allow full resource and access management."
                ),
                recommendation=(
                    "Replace Owner with a workload-specific custom or built-in role, "
                    "rotate credentials, and prefer federated workload identity with "
                    "narrow assignment scope."
                ),
            )
        ]

    def _check_custom_role_wildcard(
        self,
        assignment: AzureRoleAssignment,
        definition: AzureRoleDefinition,
    ) -> list[AzureRBACFinding]:
        if not definition.is_custom:
            return []
        for permission in definition.permissions:
            if "*" not in permission.actions and "*" not in permission.data_actions:
                continue
            return [
                AzureRBACFinding(
                    check_id="AZ-RBAC-005",
                    severity=AzureRBACSeverity.HIGH,
                    scope=assignment.scope,
                    principal=assignment.principal_name,
                    role=assignment.role_name,
                    title="Custom Azure role grants wildcard permissions",
                    detail=(
                        f"Custom role '{definition.name}' assigned to "
                        f"'{assignment.principal_name}' includes wildcard Actions "
                        "or DataActions, making the custom role as broad as a built-in "
                        "administrative role."
                    ),
                    recommendation=(
                        "Replace wildcard custom-role permissions with the specific "
                        "management-plane and data-plane operations required by the "
                        "workload, and use NotActions only as a backstop."
                    ),
                )
            ]
        return []

    def _check_privileged_role_assignment(
        self,
        assignment: AzureRoleAssignment,
    ) -> list[AzureRBACFinding]:
        if _normalize_role_name(assignment.role_name) != "user access administrator":
            return []
        if assignment.condition:
            return []
        return [
            AzureRBACFinding(
                check_id="AZ-RBAC-006",
                severity=AzureRBACSeverity.HIGH,
                scope=assignment.scope,
                principal=assignment.principal_name,
                role=assignment.role_name,
                title="User Access Administrator lacks assignment condition evidence",
                detail=(
                    f"Principal '{assignment.principal_name}' has User Access "
                    f"Administrator on '{assignment.scope}' with no exported "
                    "condition evidence limiting delegation."
                ),
                recommendation=(
                    "Review the assignment for PIM eligibility and add condition-based "
                    "delegation where supported. Remove standing User Access "
                    "Administrator access when delegation is not required."
                ),
            )
        ]

    def _is_untrusted_user(self, principal_name: str) -> bool:
        if not self._trusted_domains:
            return False
        domain = _extract_email_domain(principal_name)
        return domain is not None and domain not in self._trusted_domains


def load_azure_rbac_from_export(
    path: str | Path,
) -> tuple[list[AzureRoleAssignment], list[AzureRoleDefinition]]:
    """Load Azure role assignments and optional role definitions from JSON."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, list):
        assignments_raw = raw
        definitions_raw: list[Any] = []
    elif isinstance(raw, dict):
        assignments_raw = (
            raw.get("assignments")
            or raw.get("role_assignments")
            or raw.get("roleAssignments")
            or raw.get("value")
            or []
        )
        definitions_raw = (
            raw.get("role_definitions")
            or raw.get("roleDefinitions")
            or raw.get("definitions")
            or []
        )
        if "roleDefinitionName" in raw or "role_name" in raw or "properties" in raw:
            assignments_raw = [raw]
    else:
        raise ValueError("Azure RBAC export must be a JSON object or list.")

    if not isinstance(assignments_raw, list):
        raise ValueError("Azure RBAC assignments must be a JSON list.")
    if not isinstance(definitions_raw, list):
        raise ValueError("Azure RBAC role definitions must be a JSON list.")

    assignments = [
        AzureRoleAssignment.from_dict(item)
        for item in assignments_raw
        if isinstance(item, dict)
    ]
    role_definitions = [
        AzureRoleDefinition.from_dict(item)
        for item in definitions_raw
        if isinstance(item, dict)
    ]
    return assignments, role_definitions


def _normalize_role_name(value: str) -> str:
    return " ".join(str(value).strip().lower().split())


def _is_broad_scope(scope: str) -> bool:
    normalized = scope.rstrip("/").lower()
    return (
        normalized.startswith("/providers/microsoft.management/managementgroups/")
        or normalized.count("/resourcegroups/") == 0
        and normalized.startswith("/subscriptions/")
    )


def _is_guest_principal(assignment: AzureRoleAssignment) -> bool:
    return (
        assignment.principal_type.lower() in {"guest", "foreigngroup"}
        or "#ext#" in assignment.principal_name.lower()
    )


def _extract_email_domain(value: str) -> str | None:
    normalized = value.strip().lower()
    if "#ext#" in normalized:
        return "external"
    if "@" not in normalized:
        return None
    return normalized.rsplit("@", 1)[1]


def _definition_for_assignment(
    assignment: AzureRoleAssignment,
    role_map: dict[str, AzureRoleDefinition],
) -> AzureRoleDefinition | None:
    keys = [
        assignment.role_definition_id.lower(),
        assignment.role_definition_id.rstrip("/").rsplit("/", 1)[-1].lower(),
        _normalize_role_name(assignment.role_name),
    ]
    for key in keys:
        if key and key in role_map:
            return role_map[key]
    return None


def _role_definition_map(
    definitions: list[AzureRoleDefinition],
) -> dict[str, AzureRoleDefinition]:
    mapping: dict[str, AzureRoleDefinition] = {}
    for definition in definitions:
        for key in (
            definition.role_id.lower(),
            definition.role_id.rstrip("/").rsplit("/", 1)[-1].lower(),
            _normalize_role_name(definition.name),
        ):
            if key:
                mapping[key] = definition
    return mapping


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []
