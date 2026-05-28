"""
draugr_alerts.py — Email and webhook alerting for Draugr scan events.

Triggers:
  - New KEV-listed CVE found in a scan
  - Risk score crosses a configured threshold
  - New finding on a system with no previous findings
  - Diff detects newly KEV-listed CVEs since last scan

Supports:
  - SMTP email (plain text + HTML with full CVE detail tables)
  - Slack (Block Kit — formatted cards with severity colour, links, fields)
  - Microsoft Teams (Adaptive Card)
  - Generic webhook (JSON POST)
  - Config stored in draugr_alerts.json next to draugr.py
"""
import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Colour palette ────────────────────────────────────────────────────
_CLR = {
    "CRITICAL": "#cb322c",
    "HIGH":     "#d4722a",
    "MEDIUM":   "#c4935a",
    "LOW":      "#7a9e6e",
    "INFO":     "#7a8fa3",
}
_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
    "kev":         "⚠️",
    "newly_kev":   "🚨",
    "high_risk":   "🟠",
    "new_system":  "🆕",
}
_TIMEFRAME = {
    "CRITICAL": "24–72 hours",
    "HIGH":     "7 days",
    "MEDIUM":   "30 days",
    "LOW":      "90 days",
}


# ------------------------------------------------------------------
# Config management
# ------------------------------------------------------------------
_DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "alert_on_kev": True,
    "alert_on_new_system": True,
    "risk_threshold": 80.0,
    "kev_threshold": 1,
    "suppression_hours": 24,      # re-alert suppression window per (alert_type, cve_id, system_id)
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
        "type": "slack",
        "headers": {},
        "mention": "",
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
    path = _config_path()
    if not path.exists():
        save_alert_config(_DEFAULT_CONFIG)
    return path


# ------------------------------------------------------------------
# Alert suppression — prevents the same alert firing every scan cycle
# until the finding is resolved.
# Stored as a JSON dict: {suppression_key: last_alerted_timestamp}
# ------------------------------------------------------------------
def _suppression_path() -> Path:
    return Path(os.path.dirname(os.path.abspath(__file__))) / "draugr_alert_suppression.json"


def _load_suppression() -> Dict[str, float]:
    path = _suppression_path()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_suppression(store: Dict[str, float]) -> None:
    try:
        with open(_suppression_path(), "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
    except OSError:
        pass


def _suppression_key(alert_type: str, system_id: str, cve_id: str = "") -> str:
    """Stable key for one (alert_type, system, cve) combination."""
    return f"{alert_type}|{system_id}|{cve_id}"


def is_suppressed(alert_type: str, system_id: str, cve_id: str,
                  suppression_hours: float, store: Dict[str, float]) -> bool:
    """Return True if this alert fired within the suppression window."""
    import time
    key = _suppression_key(alert_type, system_id, cve_id)
    last = store.get(key)
    if last is None:
        return False
    return (time.time() - last) < suppression_hours * 3600


def record_alerts_sent(alerts: List[Dict[str, Any]],
                       store: Dict[str, float]) -> Dict[str, float]:
    """
    Stamp each CVE in each dispatched alert with the current timestamp.
    Returns the updated store (caller should persist it).
    """
    import time
    now = time.time()
    for alert in alerts:
        atype     = alert.get("type", "")
        system_id = alert.get("system_id", "")
        for row in alert.get("rows", []):
            cid = str(row.get("CVE ID", "") or "")
            key = _suppression_key(atype, system_id, cid)
            store[key] = now
        # Also stamp the alert-level key (covers new_system / newly_kev alerts)
        store[_suppression_key(atype, system_id, "")] = now
    return store


def purge_suppression_store(suppression_hours: float) -> int:
    """
    Remove entries older than the suppression window.
    Returns count of entries removed. Call periodically (e.g. at scan start).
    """
    import time
    store    = _load_suppression()
    cutoff   = time.time() - suppression_hours * 3600
    original = len(store)
    store    = {k: v for k, v in store.items() if v >= cutoff}
    _save_suppression(store)
    return original - len(store)


# ------------------------------------------------------------------
# CVE row → rich formatted strings
# ------------------------------------------------------------------
def _nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _row_plain(r: Dict[str, Any], idx: int) -> str:
    """Single CVE formatted as plain text for a numbered list."""
    cid      = r.get("CVE ID", "")
    sw       = f"{r.get('Software Name','')} {r.get('Software Version','')}".strip()
    sev      = r.get("CVSS Severity", "")
    cvss     = r.get("CVSS Base Score", "")
    rs       = r.get("Risk Score", "")
    epss     = r.get("EPSS Score", "")
    kev      = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
    expl     = str(r.get("Public Exploit","")).upper() == "YES"
    expl_src = str(r.get("Exploit Sources","") or "")
    adv_url  = str(r.get("Vendor Advisory URL","") or "")
    patch_age= str(r.get("Patch Age (Days)","") or "")
    kev_date = str(r.get("KEV Date Added","") or "")
    timeframe= _TIMEFRAME.get(sev.upper(), "30 days")

    lines = [f"  {idx}. {cid} — {sw}"]
    lines.append(f"     Severity: {sev}  |  CVSS: {cvss}  |  Risk Score: {rs}  |  EPSS: {epss}")
    if kev:
        kev_info = f" (added {kev_date})" if kev_date else ""
        lines.append(f"     ⚠ CISA KEV-LISTED{kev_info} — Active exploitation confirmed")
    if expl:
        src_txt = f" — {expl_src}" if expl_src else ""
        lines.append(f"     🔴 Public exploit code available{src_txt}")
    if patch_age and patch_age != "0 (installed after CVE published)":
        lines.append(f"     Patch age: {patch_age} days unpatched")
    lines.append(f"     ➜ Required action: Patch within {timeframe}")
    lines.append(f"     NVD: {_nvd_url(cid)}")
    if adv_url:
        adv_name = str(r.get("Vendor Advisory Name","") or "Vendor Advisory")
        lines.append(f"     {adv_name}: {adv_url}")
    return "\n".join(lines)


def _plain_body(
    alert_type: str,
    system_id: str,
    rows: List[Dict[str, Any]],
    extra_lines: Optional[List[str]] = None,
) -> str:
    """Build a complete plain-text alert body."""
    import datetime
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "=" * 60,
        f"DRAUGR THREAT INTELLIGENCE — {alert_type.upper().replace('_', ' ')}",
        "=" * 60,
        f"System:      {system_id}",
        f"Scan time:   {scan_time}",
        f"Findings:    {len(rows)}",
        "",
    ]
    if extra_lines:
        lines += extra_lines + [""]
    if rows:
        lines.append("CVE DETAILS")
        lines.append("-" * 40)
        for i, r in enumerate(rows, 1):
            lines.append(_row_plain(r, i))
            lines.append("")
    lines += [
        "-" * 60,
        "Sent by Draugr Threat Intelligence System",
        "Resolve findings via your vulnerability management programme.",
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------
# HTML email body builder
# ------------------------------------------------------------------
def _cve_table_html(rows: List[Dict[str, Any]]) -> str:
    """Build an HTML table of CVE findings for email."""
    rows_html = []
    for r in rows:
        cid      = r.get("CVE ID", "")
        sw       = f"{r.get('Software Name','')} {r.get('Software Version','')}".strip()
        sev      = str(r.get("CVSS Severity","") or "").upper()
        cvss     = r.get("CVSS Base Score", "")
        rs       = r.get("Risk Score", "")
        epss     = r.get("EPSS Score", "")
        kev      = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
        expl     = str(r.get("Public Exploit","")).upper() == "YES"
        expl_src = str(r.get("Exploit Sources","") or "")
        adv_url  = str(r.get("Vendor Advisory URL","") or "")
        adv_name = str(r.get("Vendor Advisory Name","") or "Vendor Advisory")
        patch_age= str(r.get("Patch Age (Days)","") or "")
        kev_date = str(r.get("KEV Date Added","") or "")
        nvd      = _nvd_url(cid)
        sev_clr  = _CLR.get(sev, _CLR["INFO"])
        timeframe = _TIMEFRAME.get(sev, "30 days")

        # Badges
        badges = []
        if kev:
            kd = f" ({kev_date})" if kev_date else ""
            badges.append(
                f'<span style="background:#3a0a0a;color:#cb322c;padding:2px 6px;'
                f'border-radius:3px;font-size:10px;font-weight:700;">⚠ KEV{kd}</span>'
            )
        if expl:
            src_txt = f" — {expl_src}" if expl_src else ""
            badges.append(
                f'<span style="background:#2a1000;color:#d4722a;padding:2px 6px;'
                f'border-radius:3px;font-size:10px;font-weight:700;">🔴 PUBLIC EXPLOIT{src_txt}</span>'
            )
        badge_html = " ".join(badges)

        # Patch age warning
        age_html = ""
        if patch_age and patch_age != "0 (installed after CVE published)":
            try:
                age_int = int(patch_age)
                age_clr = "#cb322c" if age_int > 90 else "#d4722a" if age_int > 30 else "#c4935a"
                age_html = (
                    f'<br><span style="color:{age_clr};font-size:10px;">'
                    f'⏱ {patch_age} days unpatched</span>'
                )
            except ValueError:
                pass

        # Links
        link_parts = [f'<a href="{nvd}" style="color:#7a8fa3;">NVD</a>']
        if adv_url:
            link_parts.append(f'<a href="{adv_url}" style="color:#7a8fa3;">{adv_name}</a>')

        rows_html.append(f"""
        <tr>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;">
            <div style="font-weight:700;color:#e4ccc8;">{cid}</div>
            <div style="font-size:11px;color:#7a5c5a;margin-top:2px;">{sw}</div>
            {age_html}
          </td>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;
                     font-weight:700;color:{sev_clr};">{sev}</td>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;
                     color:#e4ccc8;">{cvss}</td>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;
                     color:#e4ccc8;font-weight:700;">{rs}</td>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;
                     color:#7a9e6e;">{epss}</td>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;">
            {badge_html}
          </td>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;
                     font-size:11px;color:#7a8fa3;">
            {" | ".join(link_parts)}
          </td>
          <td style="padding:10px 8px;border-bottom:1px solid #1f0d0d;vertical-align:top;
                     font-size:11px;color:#c4935a;font-weight:600;">
            ≤ {timeframe}
          </td>
        </tr>""")

    table_head = """
    <table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:12px;">
      <tr style="background:#1f0d0d;">
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">CVE / SOFTWARE</th>
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">SEVERITY</th>
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">CVSS</th>
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">RISK</th>
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">EPSS</th>
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">FLAGS</th>
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">REFERENCES</th>
        <th style="padding:8px;text-align:left;color:#7a5c5a;font-size:10px;
                   letter-spacing:1px;border-bottom:2px solid #551e1e;">PATCH BY</th>
      </tr>
      {"".join(rows_html)}
    </table>"""
    return table_head


def _html_body(
    alert: Dict[str, Any],
    rows: List[Dict[str, Any]],
    extra_html: str = "",
) -> str:
    """Build a complete styled HTML email body."""
    import datetime
    scan_time  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    sev        = alert.get("severity", "INFO")
    sev_clr    = _CLR.get(sev, _CLR["INFO"])
    title      = alert["title"]
    system_id  = alert.get("system_id", "")
    emoji      = _EMOJI.get(alert.get("type",""), _EMOJI.get(sev, "⚪"))
    alert_type = alert.get("type","").replace("_"," ").upper()

    stat_boxes = ""
    if rows:
        kev_c  = sum(1 for r in rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        expl_c = sum(1 for r in rows if str(r.get("Public Exploit","")).upper() == "YES")
        crit_c = sum(1 for r in rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        max_rs = max((float(str(r.get("Risk Score",0) or 0)) for r in rows), default=0.0)
        stat_boxes = f"""
        <div style="display:flex;gap:12px;margin:16px 0;flex-wrap:wrap;">
          <div style="background:#1f0d0d;border:1px solid #551e1e;border-radius:6px;
                      padding:10px 16px;min-width:80px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#e4ccc8;">{len(rows)}</div>
            <div style="font-size:9px;color:#7a5c5a;letter-spacing:1px;">FINDINGS</div>
          </div>
          <div style="background:#3a0a0a;border:1px solid #551e1e;border-radius:6px;
                      padding:10px 16px;min-width:80px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#cb322c;">{kev_c}</div>
            <div style="font-size:9px;color:#7a5c5a;letter-spacing:1px;">KEV</div>
          </div>
          <div style="background:#2a1000;border:1px solid #551e1e;border-radius:6px;
                      padding:10px 16px;min-width:80px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#d4722a;">{expl_c}</div>
            <div style="font-size:9px;color:#7a5c5a;letter-spacing:1px;">PUBLIC EXPLOIT</div>
          </div>
          <div style="background:#1f0d0d;border:1px solid #551e1e;border-radius:6px;
                      padding:10px 16px;min-width:80px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#cb322c;">{crit_c}</div>
            <div style="font-size:9px;color:#7a5c5a;letter-spacing:1px;">CRITICAL</div>
          </div>
          <div style="background:#1f0d0d;border:1px solid #551e1e;border-radius:6px;
                      padding:10px 16px;min-width:80px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#e4ccc8;">{max_rs:.1f}</div>
            <div style="font-size:9px;color:#7a5c5a;letter-spacing:1px;">MAX RISK</div>
          </div>
        </div>"""

    cve_table = _cve_table_html(rows) if rows else ""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',sans-serif;background:#0f0505;color:#e4ccc8;
             margin:0;padding:24px;max-width:900px;">

  <!-- Header bar -->
  <div style="background:{sev_clr};border-radius:6px 6px 0 0;
              padding:12px 20px;margin-bottom:0;">
    <span style="font-size:13px;font-weight:700;color:#fff;letter-spacing:2px;">
      {emoji} DRAUGR — {alert_type}
    </span>
  </div>

  <!-- Card -->
  <div style="background:#170909;border:1px solid #551e1e;border-top:none;
              border-radius:0 0 6px 6px;padding:20px 24px;">

    <h2 style="color:{sev_clr};margin:0 0 4px 0;font-size:18px;">{title}</h2>
    <div style="color:#7a5c5a;font-size:11px;margin-bottom:16px;">
      System: <strong style="color:#e4ccc8;">{system_id}</strong>
      &nbsp;|&nbsp; Scan time: {scan_time}
    </div>

    {stat_boxes}
    {extra_html}
    {cve_table}

    <div style="margin-top:24px;padding-top:16px;border-top:1px solid #1f0d0d;
                color:#7a5c5a;font-size:10px;">
      Sent by Draugr Threat Intelligence System &nbsp;·&nbsp;
      Resolve findings via your vulnerability management programme.
    </div>
  </div>
</body></html>"""


# ------------------------------------------------------------------
# Slack Block Kit builder
# ------------------------------------------------------------------
def _slack_payload(
    alert: Dict[str, Any],
    rows: List[Dict[str, Any]],
    mention: str = "",
) -> Dict[str, Any]:
    """Build a rich Slack Block Kit payload."""
    sev       = alert.get("severity", "INFO")
    emoji     = _EMOJI.get(alert.get("type",""), _EMOJI.get(sev, "⚪"))
    title     = alert["title"]
    system_id = alert.get("system_id", "")
    alert_type= alert.get("type","").replace("_"," ").title()
    import datetime
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    blocks: List[Dict[str, Any]] = []

    # Header
    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": f"{emoji} {title}", "emoji": True}
    })

    # Summary fields
    kev_c  = sum(1 for r in rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
    expl_c = sum(1 for r in rows if str(r.get("Public Exploit","")).upper() == "YES")
    crit_c = sum(1 for r in rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
    max_rs = max((float(str(r.get("Risk Score",0) or 0)) for r in rows), default=0.0) if rows else 0.0

    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*System*\n{system_id}"},
            {"type": "mrkdwn", "text": f"*Scan Time*\n{scan_time}"},
            {"type": "mrkdwn", "text": f"*Alert Type*\n{alert_type}"},
            {"type": "mrkdwn", "text": f"*Severity*\n{sev}"},
            {"type": "mrkdwn", "text": f"*Total Findings*\n{len(rows)}"},
            {"type": "mrkdwn", "text": f"*KEV Listed*\n{'⚠️ ' + str(kev_c) if kev_c else str(kev_c)}"},
            {"type": "mrkdwn", "text": f"*Public Exploits*\n{'🔴 ' + str(expl_c) if expl_c else str(expl_c)}"},
            {"type": "mrkdwn", "text": f"*Max Risk Score*\n{max_rs:.1f}"},
        ]
    })

    blocks.append({"type": "divider"})

    # Per-CVE sections (top 5)
    for r in rows[:5]:
        cid       = r.get("CVE ID", "")
        sw        = f"{r.get('Software Name','')} {r.get('Software Version','')}".strip()
        sev_r     = str(r.get("CVSS Severity","") or "")
        cvss_r    = r.get("CVSS Base Score","")
        rs_r      = r.get("Risk Score","")
        epss_r    = r.get("EPSS Score","")
        kev_r     = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
        expl_r    = str(r.get("Public Exploit","")).upper() == "YES"
        expl_src  = str(r.get("Exploit Sources","") or "")
        adv_url   = str(r.get("Vendor Advisory URL","") or "")
        adv_name  = str(r.get("Vendor Advisory Name","") or "Vendor Advisory")
        patch_age = str(r.get("Patch Age (Days)","") or "")
        kev_date  = str(r.get("KEV Date Added","") or "")
        nvd       = _nvd_url(cid)
        timeframe = _TIMEFRAME.get(sev_r.upper(), "30 days")

        # Build flags line
        flags = []
        if kev_r:
            flags.append(f"⚠️ *KEV*{' (' + kev_date + ')' if kev_date else ''}")
        if expl_r:
            src = f" — {expl_src}" if expl_src else ""
            flags.append(f"🔴 *Public Exploit*{src}")
        if patch_age and patch_age != "0 (installed after CVE published)":
            flags.append(f"⏱ {patch_age} days unpatched")
        flags_text = "  ".join(flags) if flags else "No active exploitation confirmed"

        # Links
        links = [f"<{nvd}|NVD>"]
        if adv_url:
            links.append(f"<{adv_url}|{adv_name}>")

        cve_sev_emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(
            sev_r.upper(), "⚪"
        )

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{cve_sev_emoji} <{nvd}|{cid}>*  —  {sw}\n"
                    f"Severity: *{sev_r}*  |  CVSS: `{cvss_r}`  |  "
                    f"Risk: `{rs_r}`  |  EPSS: `{epss_r}`\n"
                    f"{flags_text}\n"
                    f"References: {' | '.join(links)}\n"
                    f"*Required action: Patch within {timeframe}*"
                )
            }
        })

    if len(rows) > 5:
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"_...and {len(rows) - 5} more finding(s). Review the full Draugr report for complete details._"
            }]
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": "Sent by *Draugr Threat Intelligence System* · Resolve via your vulnerability management programme."
        }]
    })

    # fallback text for notifications
    fallback = f"{emoji} {title} — {len(rows)} finding(s) on {system_id}"
    if mention:
        fallback = f"{mention} {fallback}"

    return {
        "text":   fallback,
        "blocks": blocks,
    }


# ------------------------------------------------------------------
# Teams Adaptive Card builder
# ------------------------------------------------------------------
def _teams_payload(
    alert: Dict[str, Any],
    rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a Microsoft Teams Adaptive Card payload."""
    sev       = alert.get("severity", "INFO")
    title     = alert["title"]
    system_id = alert.get("system_id", "")
    import datetime
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    theme_clr = {"CRITICAL":"attention","HIGH":"warning","INFO":"accent"}.get(sev,"default")

    kev_c  = sum(1 for r in rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
    expl_c = sum(1 for r in rows if str(r.get("Public Exploit","")).upper() == "YES")
    max_rs = max((float(str(r.get("Risk Score",0) or 0)) for r in rows), default=0.0) if rows else 0.0

    # Build CVE fact sets
    fact_sets = []
    for r in rows[:8]:
        cid      = r.get("CVE ID","")
        sw       = f"{r.get('Software Name','')} {r.get('Software Version','')}".strip()
        sev_r    = r.get("CVSS Severity","")
        rs_r     = r.get("Risk Score","")
        kev_r    = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
        expl_r   = str(r.get("Public Exploit","")).upper() == "YES"
        adv_url  = str(r.get("Vendor Advisory URL","") or "")
        adv_name = str(r.get("Vendor Advisory Name","") or "Vendor Advisory")
        nvd      = _nvd_url(cid)
        flags    = ("⚠ KEV " if kev_r else "") + ("🔴 EXPLOIT" if expl_r else "")
        timeframe= _TIMEFRAME.get(str(sev_r).upper(), "30 days")

        facts = [
            {"title": "Software", "value": sw},
            {"title": "Severity / Risk", "value": f"{sev_r}  |  Score: {rs_r}"},
            {"title": "Flags", "value": flags or "None"},
            {"title": "Patch by", "value": timeframe},
        ]
        links_txt = f"[NVD]({nvd})"
        if adv_url:
            links_txt += f"  |  [{adv_name}]({adv_url})"
        facts.append({"title": "References", "value": links_txt})

        fact_sets.append({
            "type": "FactSet",
            "facts": facts,
            "separator": True,
        })
        fact_sets.append({
            "type": "TextBlock",
            "text": f"**{cid}**",
            "weight": "Bolder",
            "color": theme_clr,
            "separator": True,
        })

    body = [
        {"type": "TextBlock", "text": title, "weight": "Bolder",
         "size": "Medium", "color": theme_clr, "wrap": True},
        {"type": "FactSet", "facts": [
            {"title": "System",        "value": system_id},
            {"title": "Scan Time",     "value": scan_time},
            {"title": "Findings",      "value": str(len(rows))},
            {"title": "KEV Listed",    "value": str(kev_c)},
            {"title": "Public Exploit","value": str(expl_c)},
            {"title": "Max Risk Score","value": f"{max_rs:.1f}"},
        ]},
        {"type": "TextBlock", "text": "CVE Details",
         "weight": "Bolder", "separator": True},
    ] + fact_sets

    return {
        "type":        "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.4",
                "body":    body,
            }
        }]
    }


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
    Returns a list of rich alert dicts, with already-suppressed CVEs filtered out.
    """
    if cfg is None:
        cfg = load_alert_config()
    if not cfg.get("enabled", False):
        return []

    alerts: List[Dict[str, Any]] = []
    threshold         = float(cfg.get("risk_threshold", 80.0))
    kev_thresh        = int(cfg.get("kev_threshold", 1))
    suppression_hours = float(cfg.get("suppression_hours", 24))
    sup_store         = _load_suppression()

    def _unsuppressed(atype: str, row_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return only rows not already suppressed for this alert type + system."""
        return [
            r for r in row_list
            if not is_suppressed(
                atype, system_id, str(r.get("CVE ID", "") or ""),
                suppression_hours, sup_store
            )
        ]

    kev_rows  = sorted(
        [r for r in rows if str(r.get("Known Exploited Vulnerability", "")).upper() == "YES"],
        key=lambda r: -float(str(r.get("Risk Score", 0) or 0))
    )
    high_risk = sorted(
        [r for r in rows if float(str(r.get("Risk Score", 0) or 0)) >= threshold],
        key=lambda r: -float(str(r.get("Risk Score", 0) or 0))
    )

    # ── KEV alert ─────────────────────────────────────────────────────
    if cfg.get("alert_on_kev", True):
        unsup_kev = _unsuppressed("kev", kev_rows)
        if len(unsup_kev) >= kev_thresh:
            top = unsup_kev[:8]
            body = _plain_body(
                "KEV ALERT", system_id, top,
                extra_lines=[
                    f"⚠ {len(unsup_kev)} CVE(s) have confirmed active exploitation (CISA KEV).",
                    "REQUIRED: Patch all KEV-listed findings within 24–72 hours.",
                    "CISA BOD 22-01 mandates remediation for federal agencies.",
                ]
            )
            alerts.append({
                "type":      "kev",
                "title":     f"[DRAUGR] {len(unsup_kev)} KEV-listed CVE(s) on {system_id}",
                "body":      body,
                "severity":  "CRITICAL",
                "system_id": system_id,
                "count":     len(unsup_kev),
                "rows":      top,
            })

    # ── High-risk alert ───────────────────────────────────────────────
    kev_ids   = {r.get("CVE ID", "") for r in kev_rows}
    high_only = [r for r in high_risk if r.get("CVE ID", "") not in kev_ids]
    unsup_hr  = _unsuppressed("high_risk", high_only)
    if unsup_hr:
        top_hr = unsup_hr[:8]
        body = _plain_body(
            "HIGH RISK ALERT", system_id, top_hr,
            extra_lines=[
                f"🟠 {len(unsup_hr)} CVE(s) exceeded risk threshold ({threshold}).",
                "Risk score incorporates CVSS, EPSS, KEV status, and patch age.",
                "Review and patch according to your vulnerability management SLA.",
            ]
        )
        alerts.append({
            "type":      "high_risk",
            "title":     f"[DRAUGR] {len(unsup_hr)} high-risk CVE(s) on {system_id} (score ≥{threshold:.0f})",
            "body":      body,
            "severity":  "HIGH",
            "system_id": system_id,
            "count":     len(unsup_hr),
            "rows":      top_hr,
        })

    # ── New system alert ──────────────────────────────────────────────
    if cfg.get("alert_on_new_system", True) and is_new_system:
        # New system alerts are not CVE-level suppressed — the system itself is new
        if not is_suppressed("new_system", system_id, "", suppression_hours, sup_store):
            top_new = sorted(rows, key=lambda r: -float(str(r.get("Risk Score", 0) or 0)))[:5]
            body = _plain_body(
                "NEW SYSTEM DETECTED", system_id, top_new,
                extra_lines=[
                    f"🆕 New system scanned for the first time: {system_id}",
                    f"Total findings: {len(rows)}  |  KEV: {len(kev_rows)}  |  High-risk: {len(high_risk)}",
                    "Review the full Draugr report and establish a remediation baseline.",
                ]
            )
            alerts.append({
                "type":      "new_system",
                "title":     f"[DRAUGR] New system detected: {system_id}",
                "body":      body,
                "severity":  "INFO",
                "system_id": system_id,
                "count":     1,
                "rows":      top_new,
            })

    # ── Newly KEV-listed (from diff) ──────────────────────────────────
    if diff:
        newly_kev = diff.get("newly_kev", [])
        unsup_nk  = _unsuppressed("newly_kev", newly_kev)
        if unsup_nk:
            top_nk = sorted(unsup_nk, key=lambda r: -float(str(r.get("Risk Score", 0) or 0)))[:8]
            body = _plain_body(
                "NEWLY KEV-LISTED", system_id, top_nk,
                extra_lines=[
                    f"🚨 {len(unsup_nk)} CVE(s) were added to CISA KEV since your last scan.",
                    "These were NOT confirmed exploited at the time of your previous scan.",
                    "Treat with the same urgency as KEV findings: patch within 24–72 hours.",
                ]
            )
            alerts.append({
                "type":      "newly_kev",
                "title":     f"[DRAUGR] {len(unsup_nk)} CVE(s) newly KEV-listed on {system_id}",
                "body":      body,
                "severity":  "CRITICAL",
                "system_id": system_id,
                "count":     len(unsup_nk),
                "rows":      top_nk,
            })

    return alerts


# ------------------------------------------------------------------
# SMTP delivery
# ------------------------------------------------------------------
def send_email_alert(alert: Dict[str, Any], cfg: Dict[str, Any]) -> bool:
    """Send a rich HTML + plain-text email alert. Returns True on success."""
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

    rows = alert.get("rows", [])

    msg            = MIMEMultipart("alternative")
    msg["Subject"] = alert["title"]
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)
    msg.attach(MIMEText(alert["body"], "plain"))
    msg.attach(MIMEText(_html_body(alert, rows), "html"))

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
    """Send a rich webhook alert (Slack Block Kit / Teams Adaptive Card / generic)."""
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
    rows = alert.get("rows", [])

    try:
        if wh_type == "slack":
            payload = _slack_payload(alert, rows, mention)
        elif wh_type == "teams":
            payload = _teams_payload(alert, rows)
        else:
            # Generic: structured JSON with full CVE list
            payload = {
                "title":       alert["title"],
                "body":        alert["body"],
                "severity":    alert.get("severity", "INFO"),
                "system":      alert.get("system_id", ""),
                "alert_type":  alert.get("type", ""),
                "finding_count": alert.get("count", 0),
                "source":      "draugr",
                "findings": [
                    {
                        "cve_id":    r.get("CVE ID",""),
                        "software":  f"{r.get('Software Name','')} {r.get('Software Version','')}".strip(),
                        "severity":  r.get("CVSS Severity",""),
                        "cvss":      r.get("CVSS Base Score",""),
                        "risk_score":r.get("Risk Score",""),
                        "epss":      r.get("EPSS Score",""),
                        "kev":       str(r.get("Known Exploited Vulnerability","")).upper() == "YES",
                        "exploit":   str(r.get("Public Exploit","")).upper() == "YES",
                        "patch_age": r.get("Patch Age (Days)",""),
                        "nvd_url":   _nvd_url(r.get("CVE ID","")),
                        "advisory":  r.get("Vendor Advisory URL",""),
                    }
                    for r in rows
                ],
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
    """Send all alerts via configured channels and record them in the suppression store."""
    if cfg is None:
        cfg = load_alert_config()
    if not cfg.get("enabled", False) or not alerts:
        return {"email": 0, "webhook": 0}

    email_sent   = 0
    webhook_sent = 0
    sent_alerts: List[Dict[str, Any]] = []

    for alert in alerts:
        dispatched = False
        if cfg.get("smtp", {}).get("enabled"):
            if send_email_alert(alert, cfg):
                email_sent += 1
                dispatched = True
        if cfg.get("webhook", {}).get("enabled"):
            if send_webhook_alert(alert, cfg):
                webhook_sent += 1
                dispatched = True
        if dispatched:
            sent_alerts.append(alert)

    # Persist suppression timestamps for every successfully dispatched alert
    if sent_alerts:
        sup_store = _load_suppression()
        sup_store = record_alerts_sent(sent_alerts, sup_store)
        # Purge stale entries while we have the store open
        suppression_hours = float(cfg.get("suppression_hours", 24))
        import time
        cutoff    = time.time() - suppression_hours * 3600
        sup_store = {k: v for k, v in sup_store.items() if v >= cutoff}
        _save_suppression(sup_store)

    return {"email": email_sent, "webhook": webhook_sent}
