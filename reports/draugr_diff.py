"""
draugr_diff.py — Delta / diff engine for Draugr scan results.

Compares two Draugr output CSVs and produces:
  - A structured diff dict with new/resolved/worsened/improved findings
  - An HTML diff report using the same Draugr styling
  - A plain CSV of only the changes (suitable for tracking meetings)
"""
import csv
import html
from typing import Any, Dict, List, Tuple


# ------------------------------------------------------------------
# CSV loading
# ------------------------------------------------------------------
def load_scan_csv(path: str) -> List[Dict[str, Any]]:
    """Load a Draugr output CSV into a list of row dicts."""
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return rows


def _row_key(row: Dict[str, Any]) -> Tuple[str, str]:
    """Unique key for a finding: (CVE ID, Software Name)."""
    return (
        str(row.get("CVE ID", "") or "").strip(),
        str(row.get("Software Name", "") or "").strip(),
    )


def _to_float(v: Any) -> float:
    try:
        return float(str(v).replace("%", "").strip())
    except (ValueError, TypeError):
        return 0.0


# ------------------------------------------------------------------
# Core diff engine
# ------------------------------------------------------------------
def compute_diff(
    old_rows: List[Dict[str, Any]],
    new_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compare two sets of Draugr scan rows.

    Returns a dict with:
      new         — findings in new scan not present in old scan
      resolved    — findings in old scan not present in new scan
      worsened    — findings present in both where risk score increased ≥5 pts
      improved    — findings present in both where risk score decreased ≥5 pts
      unchanged   — findings present in both with no significant score change
      kev_delta   — net change in KEV-listed count
      stats       — summary counts
    """
    old_map = {_row_key(r): r for r in old_rows}
    new_map = {_row_key(r): r for r in new_rows}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    new_findings     = [new_map[k] for k in sorted(new_keys - old_keys)]
    resolved         = [old_map[k] for k in sorted(old_keys - new_keys)]
    worsened         = []
    improved         = []
    unchanged        = []

    for k in sorted(old_keys & new_keys):
        old_r  = old_map[k]
        new_r  = new_map[k]
        old_rs = _to_float(old_r.get("Risk Score", 0))
        new_rs = _to_float(new_r.get("Risk Score", 0))
        delta  = new_rs - old_rs
        entry  = {"old": old_r, "new": new_r, "delta": round(delta, 1)}
        if delta >= 5:
            worsened.append(entry)
        elif delta <= -5:
            improved.append(entry)
        else:
            unchanged.append(entry)

    # Sort worsened by delta descending, improved by delta ascending
    worsened.sort(key=lambda e: e["delta"], reverse=True)
    improved.sort(key=lambda e: e["delta"])

    # KEV delta
    old_kev = sum(1 for r in old_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
    new_kev = sum(1 for r in new_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")

    # New KEVs: findings that exist in both but KEV status changed old→new
    newly_kev = []
    for k in old_keys & new_keys:
        was_kev = str(old_map[k].get("Known Exploited Vulnerability","")).upper() == "YES"
        is_kev  = str(new_map[k].get("Known Exploited Vulnerability","")).upper() == "YES"
        if not was_kev and is_kev:
            newly_kev.append(new_map[k])

    return {
        "new":       new_findings,
        "resolved":  resolved,
        "worsened":  worsened,
        "improved":  improved,
        "unchanged": unchanged,
        "newly_kev": newly_kev,
        "kev_delta": new_kev - old_kev,
        "stats": {
            "old_total":    len(old_rows),
            "new_total":    len(new_rows),
            "new_findings": len(new_findings),
            "resolved":     len(resolved),
            "worsened":     len(worsened),
            "improved":     len(improved),
            "unchanged":    len(unchanged),
            "old_kev":      old_kev,
            "new_kev":      new_kev,
            "newly_kev":    len(newly_kev),
            "net_change":   len(new_rows) - len(old_rows),
        },
    }


# ------------------------------------------------------------------
# HTML diff report
# ------------------------------------------------------------------
_DIFF_CSS = """
body { font-family: 'Segoe UI', sans-serif; background: #170909; color: #e4ccc8; margin: 0; padding: 24px; }
h1 { color: #cb322c; font-size: 28px; margin-bottom: 4px; }
h2 { color: #cb322c; font-size: 16px; border-left: 3px solid #cb322c; padding-left: 10px; margin-top: 32px; }
h3 { color: #e4ccc8; font-size: 13px; margin: 8px 0 4px; }
.subtitle { color: #7a5c5a; font-size: 13px; }
.stat-grid { display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }
.stat-card { background: #1f0d0d; border: 1px solid #551e1e; border-radius: 8px;
             padding: 14px 20px; min-width: 120px; }
.stat-card .val { font-size: 28px; font-weight: 700; }
.stat-card .lbl { font-size: 11px; color: #7a5c5a; letter-spacing: 1px; }
.new    .val { color: #cb322c; }
.resolved .val { color: #7a9e6e; }
.worsened .val { color: #d4722a; }
.improved .val { color: #7a9e6e; }
.kev    .val { color: #d4722a; }
table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 12px 0; }
th { background: #1f0d0d; color: #7a5c5a; text-align: left; padding: 8px 10px;
     border-bottom: 1px solid #551e1e; font-weight: 600; letter-spacing: 0.5px; }
td { padding: 7px 10px; border-bottom: 1px solid #1f0d0d; vertical-align: top; }
tr:hover td { background: #1f0d0d; }
.badge-new  { background: #3a0a0a; color: #cb322c; padding: 2px 7px;
              border-radius: 4px; font-size: 10px; font-weight: 700; }
.badge-res  { background: #0a1f0a; color: #7a9e6e; padding: 2px 7px;
              border-radius: 4px; font-size: 10px; font-weight: 700; }
.badge-wors { background: #2a1400; color: #d4722a; padding: 2px 7px;
              border-radius: 4px; font-size: 10px; font-weight: 700; }
.badge-impr { background: #0a1f0a; color: #7a9e6e; padding: 2px 7px;
              border-radius: 4px; font-size: 10px; font-weight: 700; }
.badge-kev  { background: #2a0a00; color: #d4722a; padding: 2px 6px;
              border-radius: 4px; font-size: 10px; font-weight: 700; }
a { color: #7a8fa3; }
.toc { background: #1f0d0d; border: 1px solid #551e1e; border-radius: 4px;
       padding: 14px 22px; margin: 20px 0; font-size: 12px; }
.toc ol { padding-left: 20px; margin: 6px 0 0; }
.toc li { padding: 2px 0; }
.toc a { color: #7a8fa3; text-decoration: none; }
"""

def _e(s: Any) -> str:
    return html.escape(str(s or ""))

def _nvd(cid: str) -> str:
    url = f"https://nvd.nist.gov/vuln/detail/{cid}"
    return f'<a href="{url}" target="_blank">{_e(cid)}</a>'

def _sev_style(sev: str) -> str:
    colours = {"CRITICAL": "#cb322c", "HIGH": "#d4722a", "MEDIUM": "#c4935a", "LOW": "#7a9e6e"}
    return f'color:{colours.get(sev.upper(), "#e4ccc8")};font-weight:700'


def build_diff_report(
    diff: Dict[str, Any],
    old_label: str = "Previous Scan",
    new_label: str = "Current Scan",
    report_title: str = "Draugr Delta Report",
) -> str:
    """Build a self-contained HTML diff report from a compute_diff() result."""
    import datetime
    stats = diff["stats"]
    now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    net   = stats["net_change"]
    net_s = f"+{net}" if net > 0 else str(net)
    net_colour = "#cb322c" if net > 0 else ("#7a9e6e" if net < 0 else "#e4ccc8")

    kev_delta  = diff["kev_delta"]
    kev_delta_s = f"+{kev_delta}" if kev_delta > 0 else str(kev_delta)

    parts: List[str] = []

    # Header
    parts.append(f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>{_e(report_title)}</title>
<style>{_DIFF_CSS}</style></head><body>
<h1>DRAUGR — Delta Report</h1>
<span class="subtitle">{_e(old_label)} → {_e(new_label)} &nbsp;|&nbsp; Generated: {now}</span>
""")

    # TOC
    parts.append("""<div class="toc"><strong>Contents</strong><ol>
<li><a href="#summary">Summary</a></li>
<li><a href="#new">New Findings</a></li>
<li><a href="#resolved">Resolved Findings</a></li>
<li><a href="#newly-kev">Newly KEV-Listed</a></li>
<li><a href="#worsened">Worsened</a></li>
<li><a href="#improved">Improved</a></li>
</ol></div>""")

    # Stat grid
    parts.append(f"""<div class="stat-grid" id="summary">
<div class="stat-card"><div class="lbl">OLD TOTAL</div><div class="val">{stats['old_total']}</div></div>
<div class="stat-card"><div class="lbl">NEW TOTAL</div><div class="val">{stats['new_total']}</div></div>
<div class="stat-card new"><div class="lbl">NEW FINDINGS</div><div class="val">{stats['new_findings']}</div></div>
<div class="stat-card resolved"><div class="lbl">RESOLVED</div><div class="val">{stats['resolved']}</div></div>
<div class="stat-card worsened"><div class="lbl">WORSENED</div><div class="val">{stats['worsened']}</div></div>
<div class="stat-card improved"><div class="lbl">IMPROVED</div><div class="val">{stats['improved']}</div></div>
<div class="stat-card kev"><div class="lbl">KEV DELTA</div><div class="val" style="color:{net_colour}">{kev_delta_s}</div></div>
<div class="stat-card"><div class="lbl">NET CHANGE</div><div class="val" style="color:{net_colour}">{net_s}</div></div>
</div>""")

    # ── New findings ───────────────────────────────────────────────────
    parts.append('<h2 id="new">New Findings</h2>')
    if diff["new"]:
        parts.append('<table><tr><th>CVE</th><th>Software</th><th>Severity</th>'
                     '<th>Risk Score</th><th>KEV</th><th>Exploit</th></tr>')
        for r in sorted(diff["new"], key=lambda x: -_to_float(x.get("Risk Score", 0))):
            cid  = r.get("CVE ID","")
            sev  = str(r.get("CVSS Severity","") or "").upper()
            rs   = r.get("Risk Score","")
            kev  = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
            expl = str(r.get("Public Exploit","")).upper() == "YES"
            parts.append(
                f'<tr><td>{_nvd(cid)} <span class="badge-new">NEW</span></td>'
                f'<td>{_e(r.get("Software Name",""))} {_e(r.get("Software Version",""))}</td>'
                f'<td style="{_sev_style(sev)}">{sev}</td>'
                f'<td>{_e(rs)}</td>'
                f'<td>{"⚠ YES" if kev else "No"}</td>'
                f'<td>{"Yes" if expl else "No"}</td></tr>'
            )
        parts.append("</table>")
    else:
        parts.append("<p>No new findings.</p>")

    # ── Resolved findings ──────────────────────────────────────────────
    parts.append('<h2 id="resolved">Resolved Findings</h2>')
    if diff["resolved"]:
        parts.append('<table><tr><th>CVE</th><th>Software</th><th>Severity</th>'
                     '<th>Previous Risk Score</th></tr>')
        for r in sorted(diff["resolved"], key=lambda x: -_to_float(x.get("Risk Score", 0))):
            cid = r.get("CVE ID","")
            sev = str(r.get("CVSS Severity","") or "").upper()
            rs  = r.get("Risk Score","")
            parts.append(
                f'<tr><td>{_nvd(cid)} <span class="badge-res">RESOLVED</span></td>'
                f'<td>{_e(r.get("Software Name",""))} {_e(r.get("Software Version",""))}</td>'
                f'<td style="{_sev_style(sev)}">{sev}</td>'
                f'<td>{_e(rs)}</td></tr>'
            )
        parts.append("</table>")
    else:
        parts.append("<p>No findings resolved.</p>")

    # ── Newly KEV-listed ───────────────────────────────────────────────
    parts.append('<h2 id="newly-kev">Newly KEV-Listed (since last scan)</h2>')
    if diff["newly_kev"]:
        parts.append('<table><tr><th>CVE</th><th>Software</th><th>Severity</th>'
                     '<th>Risk Score</th></tr>')
        for r in diff["newly_kev"]:
            cid = r.get("CVE ID","")
            sev = str(r.get("CVSS Severity","") or "").upper()
            rs  = r.get("Risk Score","")
            parts.append(
                f'<tr><td>{_nvd(cid)} <span class="badge-kev">NOW KEV</span></td>'
                f'<td>{_e(r.get("Software Name",""))} {_e(r.get("Software Version",""))}</td>'
                f'<td style="{_sev_style(sev)}">{sev}</td>'
                f'<td>{_e(rs)}</td></tr>'
            )
        parts.append("</table>")
    else:
        parts.append("<p>No CVEs newly added to KEV catalog since last scan.</p>")

    # ── Worsened ───────────────────────────────────────────────────────
    parts.append('<h2 id="worsened">Worsened Findings (risk score increased ≥5 pts)</h2>')
    if diff["worsened"]:
        parts.append('<table><tr><th>CVE</th><th>Software</th><th>Old Score</th>'
                     '<th>New Score</th><th>Delta</th></tr>')
        for e in diff["worsened"]:
            cid    = e["new"].get("CVE ID","")
            old_rs = _to_float(e["old"].get("Risk Score",0))
            new_rs = _to_float(e["new"].get("Risk Score",0))
            delta  = e["delta"]
            parts.append(
                f'<tr><td>{_nvd(cid)} <span class="badge-wors">WORSENED</span></td>'
                f'<td>{_e(e["new"].get("Software Name",""))} {_e(e["new"].get("Software Version",""))}</td>'
                f'<td>{old_rs:.1f}</td><td>{new_rs:.1f}</td>'
                f'<td style="color:#d4722a;font-weight:700">+{delta:.1f}</td></tr>'
            )
        parts.append("</table>")
    else:
        parts.append("<p>No findings worsened.</p>")

    # ── Improved ───────────────────────────────────────────────────────
    parts.append('<h2 id="improved">Improved Findings (risk score decreased ≥5 pts)</h2>')
    if diff["improved"]:
        parts.append('<table><tr><th>CVE</th><th>Software</th><th>Old Score</th>'
                     '<th>New Score</th><th>Delta</th></tr>')
        for e in diff["improved"]:
            cid    = e["new"].get("CVE ID","")
            old_rs = _to_float(e["old"].get("Risk Score",0))
            new_rs = _to_float(e["new"].get("Risk Score",0))
            delta  = e["delta"]
            parts.append(
                f'<tr><td>{_nvd(cid)} <span class="badge-impr">IMPROVED</span></td>'
                f'<td>{_e(e["new"].get("Software Name",""))} {_e(e["new"].get("Software Version",""))}</td>'
                f'<td>{old_rs:.1f}</td><td>{new_rs:.1f}</td>'
                f'<td style="color:#7a9e6e;font-weight:700">{delta:.1f}</td></tr>'
            )
        parts.append("</table>")
    else:
        parts.append("<p>No findings improved.</p>")

    parts.append("</body></html>")
    return "".join(parts)


def export_diff_csv(diff: Dict[str, Any], out_path: str) -> int:
    """
    Write a flat CSV of only changed findings (new, resolved, worsened, improved).
    Returns the number of rows written.
    """
    fieldnames = [
        "Change Type", "CVE ID", "Software Name", "Software Version",
        "Old Risk Score", "New Risk Score", "Delta", "CVSS Severity",
        "Known Exploited Vulnerability", "Public Exploit", "NVD URL",
    ]
    rows_out = []

    for r in diff["new"]:
        rows_out.append({
            "Change Type": "NEW",
            "CVE ID": r.get("CVE ID",""),
            "Software Name": r.get("Software Name",""),
            "Software Version": r.get("Software Version",""),
            "Old Risk Score": "",
            "New Risk Score": r.get("Risk Score",""),
            "Delta": r.get("Risk Score",""),
            "CVSS Severity": r.get("CVSS Severity",""),
            "Known Exploited Vulnerability": r.get("Known Exploited Vulnerability",""),
            "Public Exploit": r.get("Public Exploit",""),
            "NVD URL": r.get("NVD URL","") or f"https://nvd.nist.gov/vuln/detail/{r.get('CVE ID','')}",
        })
    for r in diff["resolved"]:
        rows_out.append({
            "Change Type": "RESOLVED",
            "CVE ID": r.get("CVE ID",""),
            "Software Name": r.get("Software Name",""),
            "Software Version": r.get("Software Version",""),
            "Old Risk Score": r.get("Risk Score",""),
            "New Risk Score": "",
            "Delta": "",
            "CVSS Severity": r.get("CVSS Severity",""),
            "Known Exploited Vulnerability": r.get("Known Exploited Vulnerability",""),
            "Public Exploit": r.get("Public Exploit",""),
            "NVD URL": r.get("NVD URL","") or f"https://nvd.nist.gov/vuln/detail/{r.get('CVE ID','')}",
        })
    for e in diff["worsened"] + diff["improved"]:
        change_type = "WORSENED" if e["delta"] > 0 else "IMPROVED"
        r = e["new"]
        rows_out.append({
            "Change Type": change_type,
            "CVE ID": r.get("CVE ID",""),
            "Software Name": r.get("Software Name",""),
            "Software Version": r.get("Software Version",""),
            "Old Risk Score": e["old"].get("Risk Score",""),
            "New Risk Score": r.get("Risk Score",""),
            "Delta": f"{e['delta']:+.1f}",
            "CVSS Severity": r.get("CVSS Severity",""),
            "Known Exploited Vulnerability": r.get("Known Exploited Vulnerability",""),
            "Public Exploit": r.get("Public Exploit",""),
            "NVD URL": r.get("NVD URL","") or f"https://nvd.nist.gov/vuln/detail/{r.get('CVE ID','')}",
        })

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)
    return len(rows_out)
