"""Alerting and notification integrations.

This module provides a small, production-oriented dispatcher for sending
notifications when critical findings are detected or when new exposures appear.

Supported channels:
- Slack incoming webhook
- Generic webhook (JSON payload)
- SMTP email

Configuration is environment-variable based to simplify CI/CD and action usage.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Dict, Iterable, List, Optional
from urllib import request
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AlertConfig:
    """Notification channel configuration loaded from environment variables."""

    slack_webhook_url: Optional[str]
    webhook_url: Optional[str]
    webhook_auth_header: Optional[str]
    email_enabled: bool
    smtp_host: Optional[str]
    smtp_port: int
    smtp_username: Optional[str]
    smtp_password: Optional[str]
    smtp_use_tls: bool
    email_from: Optional[str]
    email_to: List[str]

    @classmethod
    def from_env(cls) -> "AlertConfig":
        email_to_raw = os.getenv("CPW_ALERT_EMAIL_TO", "")
        email_to = [x.strip() for x in email_to_raw.split(",") if x.strip()]
        return cls(
            slack_webhook_url=os.getenv("CPW_ALERT_SLACK_WEBHOOK_URL") or None,
            webhook_url=os.getenv("CPW_ALERT_WEBHOOK_URL") or None,
            webhook_auth_header=os.getenv("CPW_ALERT_WEBHOOK_AUTH_HEADER") or None,
            email_enabled=(os.getenv("CPW_ALERT_EMAIL_ENABLED", "false").lower() == "true"),
            smtp_host=os.getenv("CPW_ALERT_SMTP_HOST") or None,
            smtp_port=int(os.getenv("CPW_ALERT_SMTP_PORT", "587")),
            smtp_username=os.getenv("CPW_ALERT_SMTP_USERNAME") or None,
            smtp_password=os.getenv("CPW_ALERT_SMTP_PASSWORD") or None,
            smtp_use_tls=(os.getenv("CPW_ALERT_SMTP_USE_TLS", "true").lower() == "true"),
            email_from=os.getenv("CPW_ALERT_EMAIL_FROM") or None,
            email_to=email_to,
        )


def _post_json(url: str, payload: Dict[str, Any], auth_header: Optional[str] = None, timeout: int = 10) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if auth_header:
        # Accept either `Bearer x` style or full `Header-Name: value`.
        if ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()
        else:
            headers["Authorization"] = auth_header.strip()

    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - controlled URL by operator config
        if getattr(resp, "status", 200) >= 400:
            raise RuntimeError(f"Notification POST failed with status={resp.status}")


def _send_email(
    smtp_host: str,
    smtp_port: int,
    smtp_username: Optional[str],
    smtp_password: Optional[str],
    smtp_use_tls: bool,
    email_from: str,
    email_to: Iterable[str],
    subject: str,
    body: str,
) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = email_from
    msg["To"] = ", ".join(email_to)
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
        if smtp_use_tls:
            server.starttls()
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        server.send_message(msg)


def _summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    critical = 0
    new_exposure = 0
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        typ = str(f.get("type", "")).lower()
        if sev == "critical":
            critical += 1
        if "new_exposure" in typ or f.get("is_new_exposure") is True:
            new_exposure += 1
    return {"critical": critical, "new_exposure": new_exposure, "total": len(findings)}


def dispatch_alerts(findings: List[Dict[str, Any]], run_context: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    """Dispatch alerts across configured channels.

    Args:
        findings: List of finding dictionaries from analyzers/watch mode.
        run_context: Optional context (account/project, provider, report path, etc.).

    Returns:
        Dict with channel delivery booleans.
    """
    run_context = run_context or {}
    cfg = AlertConfig.from_env()

    summary = _summarize_findings(findings)
    should_alert = summary["critical"] > 0 or summary["new_exposure"] > 0
    if not should_alert:
        logger.debug("No critical findings or new exposures; skipping notifications")
        return {"slack": False, "webhook": False, "email": False}

    title = "cloud-posture-watch alert"
    subject = (
        f"[cloud-posture-watch] critical={summary['critical']} "
        f"new_exposure={summary['new_exposure']} total={summary['total']}"
    )
    payload = {
        "title": title,
        "summary": summary,
        "run_context": run_context,
        "findings": findings,
    }

    text = (
        f"{subject}\n"
        f"context={json.dumps(run_context, sort_keys=True)}"
    )

    delivered = {"slack": False, "webhook": False, "email": False}

    if cfg.slack_webhook_url:
        try:
            _post_json(cfg.slack_webhook_url, {"text": text, "attachments": [{"text": json.dumps(payload)}]})
            delivered["slack"] = True
        except (URLError, HTTPError, OSError, RuntimeError, ValueError) as exc:
            logger.warning("Slack notification failed: %s", exc)

    if cfg.webhook_url:
        try:
            _post_json(cfg.webhook_url, payload, auth_header=cfg.webhook_auth_header)
            delivered["webhook"] = True
        except (URLError, HTTPError, OSError, RuntimeError, ValueError) as exc:
            logger.warning("Webhook notification failed: %s", exc)

    if cfg.email_enabled:
        if cfg.smtp_host and cfg.email_from and cfg.email_to:
            try:
                _send_email(
                    smtp_host=cfg.smtp_host,
                    smtp_port=cfg.smtp_port,
                    smtp_username=cfg.smtp_username,
                    smtp_password=cfg.smtp_password,
                    smtp_use_tls=cfg.smtp_use_tls,
                    email_from=cfg.email_from,
                    email_to=cfg.email_to,
                    subject=subject,
                    body=json.dumps(payload, indent=2, sort_keys=True),
                )
                delivered["email"] = True
            except (smtplib.SMTPException, OSError, ValueError) as exc:
                logger.warning("Email notification failed: %s", exc)
        else:
            logger.warning("Email alerting enabled but SMTP/email configuration is incomplete")

    return delivered
