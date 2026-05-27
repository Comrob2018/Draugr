"""
draugr_alerts.py — Email and webhook alerting for Draugr scan events.

Triggers:
  - New KEV-listed CVE found in a scan
  - Risk score crosses a configured threshold
  - New finding on a system with no previous findings
  - Diff detects newly KEV-listed CVEs since last scan

Supports:
  - SMTP email (plain text + HTML)
  - Slack / Teams / generic webhook (JSON POST)
  - Config stored in draugr_alerts.json next to draugr.py
"""
import json
import os
import re
import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ------------------------------------------------------------------
# Config management
# ------------------------------------------------------------------
_DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "alert_on_kev": True,
    "alert_on_new_system": True,
    "risk_threshold": 80.0,          # alert if any CVE risk score >= this
    "kev_threshold": 1,              # alert if KEV count >= this
    "smtp": {
        "enabled": False,
        "host": "",
        "port": 587,
        "use_tls": True,
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addrs": [],
    },
    "webhook": {
        "enabled": False,
        "url": "",
        "type": "slack",             # "slack" | "teams" | "generic"
        "headers": {},               # extra headers for generic webhooks
        "mention": "",               # @channel / @here for Slack
    },
}

def _config_path() -> Path:
    return Path(os.path.dirname(os.path.abspath(__file__))) / "draugr_alerts.json"

def load_alert_config() -> Dict[str, Any]:
    path = _config_path()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # Merge with defaults so new keys are always present
            merged = dict(_DEFAULT_CONFIG)
            merged.update(cfg)
            merged["smtp"]    = {**_DEFAULT_CONFIG["smtp"],    **cfg.get("smtp", {})}
            merged["webhook"] = {**_DEFAULT_CONFIG["webhook"], **cfg.get("webhook", {})}
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return dict(_DEFAULT_CONFIG)

def save_alert_config(cfg: Dict[str, Any]) -> None:
    with open(_config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def create_default_config() -> Path:
    """Write a default config file and return its path."""
    path = _config_path()
    if not path.exists():
        save_alert_config(_DEFAULT_CONFIG)
    return path


# ------------------------------------------------------------------
# Alert conditions
# ------------------------------------------------------------------
def check_alerts(
    rows: List[Dict[str, Any]],
    system_id: str,
    is_new_system: bool = False,
    diff: Optional[Dict[str, Any]] = None,
    cfg: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluate alert conditions against scan results.
    Returns a list of alert dicts: [{type, title, body, severity}, ...]
    """
    if cfg is None:
        cfg = load_alert_config()
    if not cfg.get("enabled", False):
        return []

    alerts: List[Dict[str, Any]] = []
    threshold  = float(cfg.get("risk_threshold", 80.0))
    kev_thresh = int(cfg.get("kev_threshold", 1))

    kev_rows   = [r for r in rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES"]
    high_risk  = [r for r in rows if float(str(r.get("Risk Score",0) or 0)) >= threshold]

    # Alert: KEV threshold crossed
    if cfg.get("alert_on_kev", True) and len(kev_rows) >= kev_thresh:
        top = sorted(kev_rows, key=lambda r: -float(str(r.get("Risk Score",0) or 0)))[:5]
        cve_lines = "\n".join(
            f"  • {r.get('CVE ID','')} — {r.get('Software Name','')} {r.get('Software Version','')} "
            f"(Score: {r.get('Risk Score','')})"
            for r in top
        )
        alerts.append({
            "type":     "kev",
            "title":    f"[DRAUGR] {len(kev_rows)} KEV-listed CVE(s) on {system_id}",
            "body":     f"System: {system_id}\n\nKEV-listed vulnerabilities ({len(kev_rows)}):\n{cve_lines}\n\n"
                        f"These CVEs have confirmed active exploitation. Immediate remediation required.",
            "severity": "CRITICAL",
            "system_id": system_id,
            "count":    len(kev_rows),
        })

    # Alert: high-risk CVEs
    if high_risk and len(high_risk) > 0:
        top_hr = sorted(high_risk, key=lambda r: -float(str(r.get("Risk Score",0) or 0)))[:5]
        cve_lines = "\n".join(
            f"  • {r.get('CVE ID','')} — Score: {r.get('Risk Score','')} ({r.get('CVSS Severity','')})"
            for r in top_hr
        )
        alerts.append({
            "type":     "high_risk",
            "title":    f"[DRAUGR] {len(high_risk)} high-risk CVE(s) on {system_id} (score ≥{threshold})",
            "body":     f"System: {system_id}\n\nHigh-risk findings:\n{cve_lines}\n\n"
                        f"Risk scores incorporate CVSS, EPSS, KEV status, and patch age.",
            "severity": "HIGH",
            "system_id": system_id,
            "count":    len(high_risk),
        })

    # Alert: new system
    if cfg.get("alert_on_new_system", True) and is_new_system:
        alerts.append({
            "type":     "new_system",
            "title":    f"[DRAUGR] New system detected: {system_id}",
            "body":     f"A new system has been scanned for the first time:\n  System ID: {system_id}\n\n"
                        f"Total CVEs: {len(rows)} | KEV: {len(kev_rows)} | High-risk: {len(high_risk)}\n\n"
                        f"Review the full report for details.",
            "severity": "INFO",
            "system_id": system_id,
            "count":    1,
        })

    # Alert: newly KEV-listed CVEs from diff
    if diff:
        newly_kev = diff.get("newly_kev", [])
        if newly_kev:
            lines = "\n".join(
                f"  • {r.get('CVE ID','')} — {r.get('Software Name','')} {r.get('Software Version','')}"
                for r in newly_kev[:10]
            )
            alerts.append({
                "type":     "newly_kev",
                "title":    f"[DRAUGR] {len(newly_kev)} CVE(s) newly added to KEV on {system_id}",
                "body":     f"System: {system_id}\n\nCVEs newly added to CISA KEV since last scan:\n{lines}\n\n"
                            f"These were not KEV-listed at the time of your previous scan.",
                "severity": "CRITICAL",
                "system_id": system_id,
                "count":    len(newly_kev),
            })

    return alerts


# ------------------------------------------------------------------
# SMTP delivery
# ------------------------------------------------------------------
def send_email_alert(alert: Dict[str, Any], cfg: Dict[str, Any]) -> bool:
    """Send an alert via SMTP. Returns True on success."""
    smtp_cfg = cfg.get("smtp", {})
    if not smtp_cfg.get("enabled") or not smtp_cfg.get("host"):
        return False

    host      = smtp_cfg["host"]
    port      = int(smtp_cfg.get("port", 587))
    use_tls   = smtp_cfg.get("use_tls", True)
    username  = smtp_cfg.get("username", "")
    password  = smtp_cfg.get("password", "")
    from_addr = smtp_cfg.get("from_addr", username)
    to_addrs  = smtp_cfg.get("to_addrs", [])

    if not to_addrs:
        return False

    sev_color = {"CRITICAL": "#cb322c", "HIGH": "#d4722a", "INFO": "#7a8fa3"}.get(
        alert.get("severity","INFO"), "#7a8fa3"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = alert["title"]
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)

    # Plain text part
    plain = MIMEText(alert["body"], "plain")
    # HTML part
    html_body = (
        f'<html><body style="font-family:Segoe UI,sans-serif;background:#170909;color:#e4ccc8;padding:24px;">'
        f'<h2 style="color:{sev_color};border-left:4px solid {sev_color};padding-left:12px;">'
        f'{alert["title"]}</h2>'
        f'<pre style="background:#1f0d0d;border:1px solid #551e1e;border-radius:6px;'
        f'padding:16px;font-size:13px;white-space:pre-wrap;">{alert["body"]}</pre>'
        f'<p style="color:#7a5c5a;font-size:11px;">Sent by Draugr Threat Intelligence System</p>'
        f'</body></html>'
    )
    rich = MIMEText(html_body, "html")
    msg.attach(plain)
    msg.attach(rich)

    try:
        if use_tls:
            server = smtplib.SMTP(host, port, timeout=15)
            server.ehlo()
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        if username and password:
            server.login(username, password)
        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        return True
    except Exception:
        return False


# ------------------------------------------------------------------
# Webhook delivery
# ------------------------------------------------------------------
def send_webhook_alert(alert: Dict[str, Any], cfg: Dict[str, Any]) -> bool:
    """Send an alert via webhook. Returns True on success."""
    if not HAS_REQUESTS:
        return False
    wh_cfg = cfg.get("webhook", {})
    if not wh_cfg.get("enabled") or not wh_cfg.get("url"):
        return False

    url     = wh_cfg["url"]
    wh_type = wh_cfg.get("type", "generic").lower()
    mention = wh_cfg.get("mention", "")
    headers = {"Content-Type": "application/json"}
    headers.update(wh_cfg.get("headers", {}))

    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "INFO": "🔵"}.get(
        alert.get("severity", "INFO"), "⚪"
    )
    title = alert["title"]
    body  = alert["body"]

    try:
        if wh_type == "slack":
            payload = {
                "text": f"{sev_emoji} *{title}*{' ' + mention if mention else ''}",
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": title}},
                    {"type": "section", "text": {"type": "mrkdwn", "text": f"```{body}```"}},
                ],
            }
        elif wh_type == "teams":
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "CB322C",
                "summary": title,
                "sections": [{"activityTitle": title, "text": body.replace("\n", "<br>")}],
            }
        else:
            payload = {
                "title":    title,
                "body":     body,
                "severity": alert.get("severity", "INFO"),
                "system":   alert.get("system_id", ""),
                "source":   "draugr",
            }

        resp = _requests.post(url, headers=headers, json=payload, timeout=10)
        return resp.status_code < 400
    except Exception:
        return False


# ------------------------------------------------------------------
# Dispatch
# ------------------------------------------------------------------
def dispatch_alerts(
    alerts: List[Dict[str, Any]],
    cfg: Optional[Dict[str, Any]] = None,
) -> Dict[str, int]:
    """
    Send all alerts via configured channels.
    Returns {"email": n_sent, "webhook": n_sent}.
    """
    if cfg is None:
        cfg = load_alert_config()
    if not cfg.get("enabled", False) or not alerts:
        return {"email": 0, "webhook": 0}

    email_sent   = 0
    webhook_sent = 0

    for alert in alerts:
        if cfg.get("smtp", {}).get("enabled"):
            if send_email_alert(alert, cfg):
                email_sent += 1
        if cfg.get("webhook", {}).get("enabled"):
            if send_webhook_alert(alert, cfg):
                webhook_sent += 1

    return {"email": email_sent, "webhook": webhook_sent}
