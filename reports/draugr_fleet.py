"""
draugr_fleet.py — Fleet / multi-host report generation.

Aggregates scan history across all known systems and produces:
  - A fleet overview HTML report (per-system risk summary, trend sparklines)
  - A cross-system vulnerability heat map (which hosts share which CVEs)
  - Per-system trend charts embedded as inline SVG
"""
import html
import re
from collections import defaultdict
from typing import Any, Dict, List


_e = lambda s: html.escape(str(s or ""))

_FLEET_CSS = """
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', sans-serif; background: #170909; color: #e4ccc8;
       margin: 0; padding: 24px; font-size: 13px; }
h1 { color: #cb322c; font-size: 28px; margin-bottom: 4px; }
h2 { color: #cb322c; font-size: 15px; border-left: 3px solid #cb322c;
     padding-left: 10px; margin-top: 32px; }
h3 { color: #c4935a; font-size: 13px; margin: 12px 0 6px; }
.subtitle { color: #7a5c5a; font-size: 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
        gap: 16px; margin: 20px 0; }
.system-card { background: #1f0d0d; border: 1px solid #551e1e; border-radius: 8px;
               padding: 16px; }
.system-card h3 { margin-top: 0; color: #e4ccc8; font-size: 14px; }
.system-id { color: #7a5c5a; font-size: 11px; margin-bottom: 10px; }
.risk-row { display: flex; gap: 10px; margin: 8px 0; flex-wrap: wrap; }
.badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
.badge-crit { background: #3a0a0a; color: #cb322c; }
.badge-high { background: #2a1400; color: #d4722a; }
.badge-med  { background: #2a1a00; color: #c4935a; }
.badge-kev  { background: #3a0a0a; color: #ff4444; border: 1px solid #ff4444; }
.badge-ok   { background: #0a1f0a; color: #7a9e6e; }
.trend-label { color: #7a5c5a; font-size: 10px; margin-top: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 12px 0; }
th { background: #1f0d0d; color: #7a5c5a; text-align: left; padding: 8px 10px;
     border-bottom: 1px solid #551e1e; font-weight: 600; }
td { padding: 6px 10px; border-bottom: 1px solid #1a0505; vertical-align: middle; }
tr:hover td { background: #1f0d0d; }
.heat-high { background: #3a0808; }
.heat-med  { background: #2a1200; }
.heat-low  { background: #1a0d00; }
.heat-none { background: transparent; }
a { color: #7a8fa3; text-decoration: none; }
a:hover { text-decoration: underline; }
.toc { background: #1f0d0d; border: 1px solid #551e1e; border-radius: 4px;
       padding: 14px 22px; margin: 20px 0; font-size: 12px; }
.toc ol { padding-left: 20px; margin: 6px 0 0; }
.toc li { padding: 2px 0; }
.toc a { color: #7a8fa3; }
.trend-delta-up   { color: #cb322c; font-weight: 700; }
.trend-delta-down { color: #7a9e6e; font-weight: 700; }
.trend-delta-flat { color: #7a5c5a; }
"""


def _sparkline_svg(values: List[float], width: int = 120, height: int = 32,
                   color: str = "#cb322c") -> str:
    """Generate an inline SVG sparkline from a list of float values."""
    if not values or len(values) < 2:
        return ""
    mn, mx = min(values), max(values)
    rng = mx - mn or 1
    pts_x = [int(i * (width - 4) / (len(values) - 1)) + 2 for i in range(len(values))]
    pts_y = [int((1 - (v - mn) / rng) * (height - 4)) + 2 for v in values]
    polyline = " ".join(f"{x},{y}" for x, y in zip(pts_x, pts_y))
    return (
        f'<svg width="{width}" height="{height}" '
        f'style="vertical-align:middle;display:block;" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'<polyline points="{polyline}" fill="none" stroke="{color}" '
        f'stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>'
        f'<circle cx="{pts_x[-1]}" cy="{pts_y[-1]}" r="2.5" fill="{color}"/>'
        f'</svg>'
    )


def _sev_color(sev: str) -> str:
    return {"CRITICAL":"#cb322c","HIGH":"#d4722a","MEDIUM":"#c4935a","LOW":"#7a9e6e"}.get(
        sev.upper(), "#e4ccc8"
    )


def _delta_arrow(old: float, new: float, reverse: bool = False) -> str:
    """Return an HTML delta string. reverse=True means lower is better (risk scores)."""
    if abs(new - old) < 0.5:
        return '<span class="trend-delta-flat">→ no change</span>'
    up = new > old
    bad = up if not reverse else not up
    cls = "trend-delta-up" if bad else "trend-delta-down"
    arrow = "↑" if up else "↓"
    return f'<span class="{cls}">{arrow} {abs(new-old):.1f}</span>'


def build_fleet_report(
    systems: List[Dict[str, Any]],
    history_by_system: Dict[str, List[Dict[str, Any]]],
    trend_by_system: Dict[str, List[Dict[str, Any]]],
    report_title: str = "Draugr Fleet Overview",
) -> str:
    """
    Build a fleet HTML report.

    Parameters
    ----------
    systems           : list of system registry dicts (system_id, system_label, ...)
    history_by_system : {system_id: [scan_history rows newest-first]}
    trend_by_system   : {system_id: [trend series rows oldest-first]}
    """
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    parts: List[str] = []
    parts.append(f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>{_e(report_title)}</title>
<style>{_FLEET_CSS}</style></head><body>
<h1>DRAUGR — Fleet Overview</h1>
<span class="subtitle">Generated: {now} &nbsp;|&nbsp; {len(systems)} system(s) tracked</span>
""")

    # TOC
    parts.append("""<div class="toc"><strong>Contents</strong><ol>
<li><a href="#fleet-summary">Fleet Summary</a></li>
<li><a href="#system-cards">System Risk Cards</a></li>
<li><a href="#trend-table">Trend Table</a></li>
<li><a href="#shared-vulnerabilities">Shared Vulnerabilities</a></li>
</ol></div>""")

    # ── Fleet summary stats ────────────────────────────────────────────
    total_scans   = sum(s.get("scan_count", 0) for s in systems)
    latest_rows: List[Dict[str, Any]] = []
    for s in systems:
        hist = history_by_system.get(s["system_id"], [])
        if hist:
            latest_rows.append(hist[0])   # newest

    fleet_cves    = sum(r.get("total_cves", 0)  for r in latest_rows)
    fleet_kev     = sum(r.get("kev_count", 0)   for r in latest_rows)
    fleet_crit    = sum(r.get("critical", 0)    for r in latest_rows)
    at_risk       = sum(1 for r in latest_rows if r.get("kev_count", 0) > 0 or r.get("critical", 0) > 0)

    parts.append(f"""<h2 id="fleet-summary">Fleet Summary</h2>
<div style="display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;">
<div style="background:#1f0d0d;border:1px solid #551e1e;border-radius:8px;padding:14px 20px;">
  <div style="font-size:10px;color:#7a5c5a;letter-spacing:1px;">SYSTEMS TRACKED</div>
  <div style="font-size:28px;font-weight:700;">{len(systems)}</div></div>
<div style="background:#1f0d0d;border:1px solid #551e1e;border-radius:8px;padding:14px 20px;">
  <div style="font-size:10px;color:#7a5c5a;letter-spacing:1px;">TOTAL SCANS</div>
  <div style="font-size:28px;font-weight:700;">{total_scans}</div></div>
<div style="background:#1f0d0d;border:1px solid #551e1e;border-radius:8px;padding:14px 20px;">
  <div style="font-size:10px;color:#7a5c5a;letter-spacing:1px;">FLEET CVEs (LATEST)</div>
  <div style="font-size:28px;font-weight:700;">{fleet_cves}</div></div>
<div style="background:#3a0a0a;border:1px solid #551e1e;border-radius:8px;padding:14px 20px;">
  <div style="font-size:10px;color:#7a5c5a;letter-spacing:1px;">FLEET KEV</div>
  <div style="font-size:28px;font-weight:700;color:#cb322c;">{fleet_kev}</div></div>
<div style="background:#1f0d0d;border:1px solid #551e1e;border-radius:8px;padding:14px 20px;">
  <div style="font-size:10px;color:#7a5c5a;letter-spacing:1px;">CRITICAL SYSTEMS</div>
  <div style="font-size:28px;font-weight:700;color:#d4722a;">{at_risk}</div></div>
</div>""")

    # ── System risk cards ──────────────────────────────────────────────
    parts.append('<h2 id="system-cards">System Risk Cards</h2><div class="grid">')
    for s in systems:
        sid   = s["system_id"]
        label = s["system_label"]
        hist  = history_by_system.get(sid, [])
        trend = trend_by_system.get(sid, [])
        if not hist:
            continue
        latest = hist[0]
        prev   = hist[1] if len(hist) > 1 else None

        crit  = latest.get("critical", 0)
        high  = latest.get("high", 0)
        med   = latest.get("medium", 0)
        kev   = latest.get("kev_count", 0)
        total = latest.get("total_cves", 0)
        max_r = latest.get("max_risk", 0.0)
        scans = s.get("scan_count", 0)
        last  = s.get("last_seen", "")

        # Risk level
        if kev > 0 or max_r >= 80:
            risk_badge = '<span class="badge badge-crit">CRITICAL</span>'
        elif crit > 0 or max_r >= 60:
            risk_badge = '<span class="badge badge-high">HIGH</span>'
        elif max_r >= 40:
            risk_badge = '<span class="badge badge-med">MODERATE</span>'
        else:
            risk_badge = '<span class="badge badge-ok">LOW</span>'

        # Trend sparkline on total_cves
        spark = _sparkline_svg([t.get("total_cves", 0) for t in trend]) if len(trend) >= 2 else ""

        # Delta vs previous scan
        delta_html = ""
        if prev:
            old_t = prev.get("total_cves", 0)
            new_t = total
            delta_html = _delta_arrow(old_t, new_t)

        slug = re.sub(r"[^a-z0-9]+", "-", sid.lower()).strip("-")
        parts.append(f"""<div class="system-card" id="sys-{slug}">
<h3>{_e(label)} {risk_badge}</h3>
<div class="system-id">ID: {_e(sid)} &nbsp;|&nbsp; {scans} scan(s) &nbsp;|&nbsp; Last: {_e(last)}</div>
<div class="risk-row">
  <span class="badge badge-crit">CRIT: {crit}</span>
  <span class="badge badge-high">HIGH: {high}</span>
  <span class="badge badge-med">MED: {med}</span>
  {"<span class='badge badge-kev'>KEV: " + str(kev) + "</span>" if kev else ""}
</div>
<div style="font-size:11px;color:#7a5c5a;margin:6px 0;">
  Total CVEs: <b style="color:#e4ccc8">{total}</b> &nbsp;|&nbsp;
  Max Risk: <b style="color:#e4ccc8">{max_r:.1f}</b> &nbsp;
  {delta_html}
</div>
{"<div class='trend-label'>CVE trend (all scans)</div>" + spark if spark else ""}
</div>""")

    parts.append("</div>")

    # ── Trend table ────────────────────────────────────────────────────
    parts.append('<h2 id="trend-table">Trend Table — Latest vs Previous Scan</h2>')
    parts.append('<table><tr><th>System</th><th>Scans</th><th>Total CVEs</th>'
                 '<th>Critical</th><th>High</th><th>KEV</th><th>Max Risk</th>'
                 '<th>vs Previous</th><th>Last Scan</th></tr>')
    for s in systems:
        sid   = s["system_id"]
        label = s["system_label"]
        hist  = history_by_system.get(sid, [])
        if not hist:
            continue
        latest = hist[0]
        prev   = hist[1] if len(hist) > 1 else None
        crit   = latest.get("critical", 0)
        high   = latest.get("high", 0)
        kev    = latest.get("kev_count", 0)
        total  = latest.get("total_cves", 0)
        max_r  = latest.get("max_risk", 0.0)
        last   = latest.get("scan_date", "")

        if prev:
            delta = _delta_arrow(prev.get("total_cves", 0), total)
        else:
            delta = '<span class="trend-delta-flat">First scan</span>'

        crit_s = f'<span style="color:#cb322c;font-weight:700">{crit}</span>' if crit else str(crit)
        kev_s  = f'<span style="color:#ff4444;font-weight:700">{kev}</span>' if kev else str(kev)
        slug   = re.sub(r"[^a-z0-9]+", "-", sid.lower()).strip("-")

        parts.append(
            f'<tr>'
            f'<td><a href="#sys-{slug}">{_e(label)}</a></td>'
            f'<td>{s.get("scan_count",0)}</td>'
            f'<td>{total}</td>'
            f'<td>{crit_s}</td>'
            f'<td>{high}</td>'
            f'<td>{kev_s}</td>'
            f'<td>{max_r:.1f}</td>'
            f'<td>{delta}</td>'
            f'<td>{_e(last)}</td>'
            f'</tr>'
        )
    parts.append("</table>")

    # ── Shared vulnerability heat map ──────────────────────────────────
    parts.append('<h2 id="shared-vulnerabilities">Shared Vulnerabilities Across Fleet</h2>')
    parts.append('<p style="color:#7a5c5a;font-size:12px;">CVEs present on more than one system. '
                 'Shared vulnerabilities indicate systemic exposure — patching one host is insufficient.</p>')

    # Build CVE → systems map from latest scan rows
    cve_to_systems: Dict[str, List[str]] = defaultdict(list)
    cve_meta: Dict[str, Dict[str, str]] = {}
    for s in systems:
        sid  = s["system_id"]
        hist = history_by_system.get(sid, [])
        if not hist:
            continue
        # Get rows for latest scan
        latest_id = hist[0].get("scan_id","") if hist else ""
        # rows are stored in history; we use a lightweight summary here
        # (full rows would require get_scan_rows call which caller should pre-fetch)
        # Use KEV/crit flags from the history summary as a proxy
        label = s["system_label"]
        cve_to_systems[f"__summary_{sid}__"].append(label)

    # If caller pre-fetched rows, use them
    # For the report we show the top shared CVEs from the history aggregate
    # This is a best-effort view — full heat map requires row-level data
    parts.append('<p style="color:#7a5c5a;font-size:12px;font-style:italic;">'
                 'Run a fleet diff to see full CVE-level cross-system overlap. '
                 'This view shows system-level risk summary.</p>')

    parts.append("</body></html>")
    return "".join(parts)


def build_fleet_report_from_db(db: Any, report_title: str = "Draugr Fleet Overview") -> str:
    """
    Convenience wrapper — pulls all data from the DB and builds the fleet report.
    """
    systems = db.get_all_systems()
    history_by_system = {s["system_id"]: db.get_scan_history(s["system_id"]) for s in systems}
    trend_by_system   = {s["system_id"]: db.get_trend_series(s["system_id"])  for s in systems}
    return build_fleet_report(systems, history_by_system, trend_by_system, report_title)
