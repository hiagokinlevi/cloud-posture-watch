"""Resolvedor de rotas SOAR para eventos normalizados de cloud security."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


SOAR_ROOT = Path(__file__).resolve().parent
DEFAULT_RULES_PATH = SOAR_ROOT / "rules" / "cloud_response_rules.yaml"
DEFAULT_APPROVAL_PATH = SOAR_ROOT / "configs" / "default_approval.yaml"
DEFAULT_PLAYBOOK_PATH = Path("docs/cloud-soar.md")


@dataclass(frozen=True)
class ResolvedSoarRoute:
    """Representa a rota operacional escolhida para um evento."""

    matched: bool
    rule_id: str
    provider: str
    resource_type: str
    resource_name: str
    flag: str
    severity: str
    playbook: str
    approval_required: bool
    approval_mode: str
    actions: list[str]
    execution_policy: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serializa a rota para saída JSON."""
        return asdict(self)


def _read_yaml(path: Path) -> dict[str, Any]:
    """Lê um arquivo YAML de configuração e normaliza o retorno."""
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return payload


def _normalize_flag(value: str | None) -> str:
    """Padroniza flags para comparação estável."""
    return (value or "").strip().upper()


def _normalize_name(value: str | None) -> str:
    """Padroniza identificadores textuais simples."""
    return (value or "").strip().lower()


def resolve_soar_route(
    event: Mapping[str, Any],
    rules_path: Path = DEFAULT_RULES_PATH,
    approval_path: Path = DEFAULT_APPROVAL_PATH,
) -> ResolvedSoarRoute:
    """Resolve um evento normalizado para uma rota SOAR defensiva."""
    rules = _read_yaml(rules_path)
    approvals = _read_yaml(approval_path)

    provider = _normalize_name(str(event.get("provider", "")))
    resource_type = _normalize_name(str(event.get("resource_type", "")))
    resource_name = str(event.get("resource_name", "")).strip()
    flag = _normalize_flag(str(event.get("flag", "")))

    defaults = rules.get("defaults", {})
    execution_policy = approvals.get("execution_policy", {})
    approval_modes = approvals.get("approval_modes", {})

    matched_rule: dict[str, Any] | None = None
    for rule in rules.get("rules", []):
        if _normalize_name(str(rule.get("provider", ""))) != provider:
            continue
        match = rule.get("match", {})
        allowed_flags = {_normalize_flag(item) for item in match.get("flags", [])}
        allowed_resource_types = {
            _normalize_name(item) for item in match.get("resource_types", [])
        }
        if flag not in allowed_flags:
            continue
        if resource_type not in allowed_resource_types:
            continue
        matched_rule = rule
        break

    if matched_rule:
        route = matched_rule.get("route", {})
        severity = _normalize_name(str(route.get("severity", defaults.get("severity", "medium"))))
        approval_required = bool(route.get("approval_required", defaults.get("approval_required", True)))
        actions = [str(item) for item in route.get("actions", defaults.get("actions", []))]
        playbook = str(route.get("playbook", DEFAULT_PLAYBOOK_PATH))
        rule_id = str(matched_rule.get("id", "UNSPECIFIED"))
        matched = True
    else:
        severity = _normalize_name(str(event.get("severity", defaults.get("severity", "medium"))))
        approval_required = bool(defaults.get("approval_required", True))
        actions = [str(item) for item in defaults.get("actions", [])]
        playbook = str(DEFAULT_PLAYBOOK_PATH)
        rule_id = "DEFAULT"
        matched = False

    approval_mode = str(approval_modes.get(severity, "recommended"))

    return ResolvedSoarRoute(
        matched=matched,
        rule_id=rule_id,
        provider=provider,
        resource_type=resource_type,
        resource_name=resource_name,
        flag=flag,
        severity=severity,
        playbook=playbook,
        approval_required=approval_required,
        approval_mode=approval_mode,
        actions=actions,
        execution_policy=dict(execution_policy),
    )
