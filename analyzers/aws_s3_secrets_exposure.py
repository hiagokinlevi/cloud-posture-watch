from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


# Targeted high-signal regexes for common credential/secret formats.
SECRET_PATTERNS: List[tuple[str, re.Pattern[str], str]] = [
    (
        "aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "high",
    ),
    (
        "github_pat",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        "high",
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,80}\b"),
        "high",
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "critical",
    ),
    (
        "generic_password_assignment",
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*['\"]?[^\s'\";]{6,}"),
        "medium",
    ),
]


HIGH_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9+/=_-]{20,}\b")


@dataclass
class SecretHit:
    detector: str
    value_preview: str
    severity: str
    location: str

    def as_finding(self, bucket: str, key: str) -> Dict[str, Any]:
        return {
            "provider": "aws",
            "service": "s3",
            "category": "secrets_exposure",
            "severity": self.severity,
            "resource": f"s3://{bucket}/{key}",
            "issue": f"Potential secret detected ({self.detector})",
            "details": {
                "detector": self.detector,
                "value_preview": self.value_preview,
                "location": self.location,
            },
        }


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def _preview(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def _scan_text(text: str, location: str) -> List[SecretHit]:
    hits: List[SecretHit] = []

    for name, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(0)
            hits.append(
                SecretHit(
                    detector=name,
                    value_preview=_preview(token),
                    severity=severity,
                    location=location,
                )
            )

    # Entropy-based fallback for unknown tokens.
    for match in HIGH_ENTROPY_TOKEN.finditer(text):
        token = match.group(0)
        ent = _shannon_entropy(token)
        if ent >= 4.0 and len(token) >= 24:
            # Skip obvious non-secret URL-safe path fragments.
            if token.lower().startswith(("http", "www")):
                continue
            hits.append(
                SecretHit(
                    detector="high_entropy_token",
                    value_preview=_preview(token),
                    severity="medium",
                    location=location,
                )
            )

    # Deduplicate by detector + preview + location.
    uniq: Dict[tuple[str, str, str], SecretHit] = {}
    for hit in hits:
        uniq[(hit.detector, hit.value_preview, hit.location)] = hit
    return list(uniq.values())


def analyze_aws_s3_secrets_exposure(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyze offline AWS S3 export evidence for potential secrets in object metadata/content.

    Expected shape (best-effort, tolerant parser):
    {
      "s3": {
        "objects": [
          {
            "bucket": "name",
            "key": "path/file.txt",
            "metadata": {"k": "v"},
            "tags": {"k": "v"},
            "content": "optional text body"
          }
        ]
      }
    }
    """
    findings: List[Dict[str, Any]] = []

    s3_section = evidence.get("s3", evidence)
    objects: Iterable[Dict[str, Any]] = s3_section.get("objects", []) if isinstance(s3_section, dict) else []

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        bucket = str(obj.get("bucket", "unknown-bucket"))
        key = str(obj.get("key", "unknown-key"))

        # Metadata / tags may include credential-like literals.
        for field_name in ("metadata", "tags"):
            field_val = obj.get(field_name)
            if isinstance(field_val, dict):
                for mk, mv in field_val.items():
                    text = f"{mk}={mv}"
                    for hit in _scan_text(text, f"{field_name}.{mk}"):
                        findings.append(hit.as_finding(bucket, key))
            elif isinstance(field_val, str):
                for hit in _scan_text(field_val, field_name):
                    findings.append(hit.as_finding(bucket, key))

        # Content can be plain text or JSON-ish object.
        content = obj.get("content")
        if isinstance(content, str):
            for hit in _scan_text(content, "content"):
                findings.append(hit.as_finding(bucket, key))
        elif isinstance(content, (dict, list)):
            serialized = json.dumps(content, ensure_ascii=False)
            for hit in _scan_text(serialized, "content"):
                findings.append(hit.as_finding(bucket, key))

    return findings
