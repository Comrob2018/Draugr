"""
draugr_reports.py — Report generation for Draugr.

Contains all three report builders and their private helpers:

  build_executive_report_markdown(rows, report_title, otx_results)
      Board-ready Executive Cyber Risk Brief (Markdown → HTML).

  build_defensive_report(rows, report_title)
      Technical Security Assessment for engineers, ISSOs, RMF reviewers.

  build_redteam_report(rows, report_title, otx_results)
      Red Team Target Report — target ranking, kill chains, exploit inventory.

Extracted from draugr.py to keep the main module manageable.
All functions take pre-computed scan row dicts; no NVD/network calls are made here.
"""

# ----------------------------------------------------------------------
# Standard library
# ----------------------------------------------------------------------
import base64
import datetime
import html
import os
import re
from collections import defaultdict, Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------------------------------------------------
# Draugr companion modules (all optional — graceful fallback)
# ----------------------------------------------------------------------
try:
    from core.draugr_themes import report_css_overrides
    HAS_THEMES = True
except ImportError:
    HAS_THEMES = False
    def report_css_overrides() -> str: return ""          # type: ignore

try:
    from intelligence.draugr_ics import ics_summary_section
    HAS_ICS = True
except ImportError:
    HAS_ICS = False
    def ics_summary_section(rows) -> str: return ""       # type: ignore

try:
    from core.draugr_plugins import collect_report_sections
    HAS_PLUGINS = True
except ImportError:
    HAS_PLUGINS = False
    def collect_report_sections(rows) -> str: return ""   # type: ignore

# ----------------------------------------------------------------------
# ATT&CK scenario library
# ----------------------------------------------------------------------
try:
    from resources.mitre_attack_scenarios import (
        TECHNIQUE_SCENARIOS as SCENARIOS,
        get_tactics,
        get_impact,
    )
except ImportError:
    SCENARIOS: Dict[str, Any] = {}                        # type: ignore
    def get_tactics(tid: str) -> List[str]: return []     # type: ignore
    def get_impact(tid: str) -> str: return ""            # type: ignore


# ----------------------------------------------------------------------
# Threat intelligence cache — shared with draugr.py.
# Populated by query_otx_for_cves / _get_cached_intel during the scan;
# read here by the report formatters to embed GreyNoise/CIRCL signal.
# Declared here so draugr.py can import it without a circular dependency.
# ----------------------------------------------------------------------
_THREAT_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}


def _split_multi(value: Any) -> List[str]:
    """Split ';' separated fields into clean unique values preserving order."""
    if value is None:
        return []
    if isinstance(value, list):
        raw = value
    else:
        raw = str(value).split(";")

    out: List[str] = []
    seen = set()
    for item in raw:
        item = str(item).strip()
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _epss_float(value: Any, default: float = 0.0) -> float:
    """Parse an EPSS value stored as '7.23%' (fmt_pct output) or raw '0.0723'."""
    try:
        s = str(value).strip().rstrip("%")
        f = float(s)
        # fmt_pct multiplies by 100 before storing, e.g. 0.0723 → '7.23%'
        # Normalise back to 0–1 so display is consistent.
        return f / 100.0 if f > 1.0 else f
    except Exception:
        return default


def _scenario_template(attack_id: str, attack_name: str, software_name: str, cve_id: str) -> str:
    """Return a short scenario narrative tied to ATT&CK technique."""
    aid = (attack_id or "").upper()

    templates = {
        "T1190": (
            f"An attacker targets a vulnerable public-facing instance of {software_name} "
            f"using {cve_id} to gain initial access, establish a foothold, and pivot to "
            f"adjacent internal systems."
        ),
        "T1068": (
            f"After exploiting {cve_id} in {software_name}, an attacker abuses the weakness "
            f"to elevate privileges and gain higher-level control over the host."
        ),
        "T1059": (
            f"Exploitation of {cve_id} in {software_name} allows the attacker to execute "
            f"commands or scripts, enabling payload delivery, persistence, or follow-on actions."
        ),
        "T1203": (
            f"A crafted exploit leveraging {cve_id} in {software_name} results in client-side "
            f"or local code execution, opening a path for malware delivery or lateral movement."
        ),
        "T1078": (
            f"An attacker uses {cve_id} in {software_name} to bypass protections or gain valid "
            f"access, then operates as a seemingly legitimate user within the environment."
        ),
        "T1499": (
            f"An attacker abuses {cve_id} in {software_name} to degrade service availability, "
            f"causing disruption to business operations or mission-critical functions."
        ),
        "T1005": (
            f"Using {cve_id} in {software_name}, an attacker accesses local data stores and "
            f"collects sensitive files, credentials, or operational information."
        ),
    }

    return templates.get(
        aid,
        f"An attacker exploits {cve_id} in {software_name} to perform ATT&CK technique "
        f"{attack_id} ({attack_name}), creating a path to compromise, disruption, or data loss."
    )

def _top_techniques(
    rows: List[Dict[str, Any]], top_n: int = 5
) -> List[Tuple[str, int, Dict[str, Any]]]:
    """
    Return the *top_n* ATT&CK techniques that appear in ``rows``.
    Each entry is (attack_id, count, meta) where *meta* contains:
        - name   : technique name
        - d3fend : list of D3FEND counter‑measures
        - nist   : list of NIST‑800‑53 controls
        - tactics: list of ATT&CK tactic names

    Rows use CSV-column keys: "ATT&CK Techniques" is a semicolon-
    separated string of "T1190 (Exploit Public-Facing Application)" entries.
    """
    technique_counter: Counter = Counter()
    technique_meta: Dict[str, Dict[str, Any]] = {}

    for r in rows:
        attacks = _split_multi(r.get("ATT&CK Techniques", ""))
        d3f     = _split_multi(r.get("D3FEND Countermeasures", ""))
        nist    = _split_multi(r.get("NIST 800-53 Controls", ""))
        tactics = _split_multi(r.get("ATT&CK Tactics", ""))

        for entry in attacks:
            m = re.match(r"^([A-Z0-9.]+)\s*\((.*?)\)$", entry)
            if m:
                aid, aname = m.group(1), m.group(2)
            else:
                aid, aname = entry.strip(), entry.strip()

            if not aid:
                continue

            technique_counter[aid] += 1
            if aid not in technique_meta:
                technique_meta[aid] = {
                    "name": aname,
                    "d3fend": list(d3f),
                    "nist": list(nist),
                    "tactics": list(tactics),
                    "d3fend_seen": set(d3f),
                    "nist_seen": set(nist),
                }
            else:
                rec = technique_meta[aid]
                for d in d3f:
                    if d not in rec["d3fend_seen"]:
                        rec["d3fend_seen"].add(d)
                        rec["d3fend"].append(d)
                for n in nist:
                    if n not in rec["nist_seen"]:
                        rec["nist_seen"].add(n)
                        rec["nist"].append(n)

    most_common = technique_counter.most_common(top_n)
    return [(aid, cnt, technique_meta[aid]) for aid, cnt in most_common]

# ======================================================================
#  HTML report helpers
# ======================================================================

def _load_logo_b64(script_dir: Optional[str] = None) -> str:
    """
    Return a src value for the report logo, in order of preference:

    1. GitHub raw URL — if a repo slug is configured in prefs.json, construct
       the raw.githubusercontent.com URL for draugr_logo_small.png on the
       main branch.  The <img> tag will fetch it at report-view time, so the
       report must be opened with internet access for the logo to appear.
       This is the preferred path: no embedding required, always up to date.

    2. Local base64 data URI — if draugr_logo_small.png exists next to the
       script it is embedded directly.  Works offline; larger HTML file.

    3. Empty string — no logo rendered; report still displays correctly.
    """
    # ── 1. GitHub raw URL ────────────────────────────────────────────
    try:
        from core.draugr_cache import _default_cache_dir
        import json as _j
        p = _default_cache_dir() / "prefs.json"
        if p.exists():
            prefs = _j.loads(p.read_text(encoding="utf-8"))
            repo  = str(prefs.get("github_repo", "") or "").strip()
            if repo:
                # Normalise: strip leading https://github.com/ if user pasted full URL
                repo = re.sub(r"^https?://github\.com/", "", repo).strip("/")
                return (
                    f"https://raw.githubusercontent.com/{repo}/main/"
                    "resources/draugr_logo_small.png"
                )
    except Exception:
        pass

    # ── 2. Local file, base64-embedded ───────────────────────────────
    search_dir = script_dir or os.path.dirname(os.path.abspath(__file__))
    for candidate in [
        os.path.join(search_dir, "resources", "draugr_logo_small.png"),
        os.path.join(search_dir, "draugr_logo_small.png"),
    ]:
        if os.path.isfile(candidate):
            try:
                with open(candidate, "rb") as fh:
                    encoded = base64.b64encode(fh.read()).decode("ascii")
                return f"data:image/png;base64,{encoded}"
            except Exception:
                break

    return ""


def _markdown_body_to_html(md: str) -> str:
    """
    Minimal markdown → HTML converter covering the subset used by the
    report builders.  Handles:
      - # / ## / ### headings
      - --- horizontal rules
      - | table | rows | (GFM-style)
      - - bullet lists (including nested indented bullets)
      - **bold** inline
      - Plain paragraphs / blank lines
    No external library required.
    """
    h = html  # alias for html.escape

    def escape(s: str) -> str:
        result = h.escape(s)
        # ATT&CK should display as "ATT&CK" — keep &amp; so it renders correctly in HTML
        # (html.escape correctly converts & → &amp;, which browsers render as &)
        return result

    def inline(s: str) -> str:
        """Apply inline transforms: **bold**, and URL auto-linking."""
        # bold
        s = re.sub(r"\*\*(.+?)\*\*", lambda m: f"<strong>{escape(m.group(1))}</strong>", s)
        # bare URLs → clickable links (open in new tab)
        s = re.sub(
            r"(?<![\"'=])(https?://[^\s<>\"']+)",
            lambda m: f'<a href="{m.group(1)}" target="_blank" rel="noopener noreferrer">{m.group(1)}</a>',
            s,
        )
        return s

    lines = md.splitlines()
    out: List[str] = []
    in_list = False
    in_table = False
    table_header_done = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def close_table():
        nonlocal in_table, table_header_done
        if in_table:
            out.append("</tbody></table>")
            in_table = False
            table_header_done = False

    for raw in lines:
        line = raw.rstrip()

        # --- Heading ---
        m = re.match(r"^(#{1,3})\s+(.*)", line)
        if m:
            close_list()
            close_table()
            level = len(m.group(1))
            text = escape(m.group(2))
            # Build a slug for anchor linking
            slug = re.sub(r"[^a-z0-9]+", "-", m.group(2).lower()).strip("-")
            toc_link = (
                ' <a href="#top" class="toc-link">↑ Top</a>'
                if level <= 2 else ""
            )
            out.append(f'<h{level} id="{slug}">{text}{toc_link}</h{level}>')
            continue

        # --- Horizontal rule ---
        if re.match(r"^---+\s*$", line):
            close_list()
            close_table()
            out.append("<hr>")
            continue

        # --- Table row ---
        if line.startswith("|"):
            close_list()
            cells = [c.strip() for c in line.strip("|").split("|")]
            # Separator row (e.g. |---|---|)
            if all(re.match(r"^:?-+:?$", c) for c in cells if c):
                if not table_header_done and in_table:
                    # Replace last <tr> as a header row
                    last = out.pop()
                    header_tr = last.replace("<tr>", "<thead><tr>").replace("</tr>", "</tr></thead><tbody>")
                    out.append(header_tr)
                    table_header_done = True
                continue
            if not in_table:
                out.append('<table>')
                in_table = True
            row_html = "".join(f"<td>{inline(escape(c))}</td>" for c in cells)
            out.append(f"<tr>{row_html}</tr>")
            continue

        # --- Bullet list item ---
        m = re.match(r"^(\s*)- (.*)", line)
        if m:
            close_table()
            if not in_list:
                out.append("<ul>")
                in_list = True
            indent = len(m.group(1))
            text = inline(escape(m.group(2)))
            style = f' style="margin-left:{indent * 12}px"' if indent else ""
            out.append(f"<li{style}>{text}</li>")
            continue

        # --- Blank line ---
        if not line.strip():
            close_list()
            close_table()
            out.append("")
            continue

        # --- Raw HTML passthrough (SVG, div wrappers, etc.) ---
        if line.startswith("<"):
            close_list()
            close_table()
            out.append(line)
            continue

        # --- Plain paragraph text ---
        close_list()
        close_table()
        out.append(f"<p>{inline(escape(line))}</p>")

    close_list()
    close_table()
    return "\n".join(out)


_REPORT_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

/* --------------------------------------------------------------
   Global page colours
   -------------------------------------------------------------- */
body {
    background: #ffffff;          /* white page background */
    color: #001f3f;               /* navy (dark blue) text */
    font-family: 'Courier New', Courier, monospace;
    font-size: 13px;
    line-height: 1.6;
    padding: 0 40px 60px 40px;
}

/* --------------------------------------------------------------
   Header
   -------------------------------------------------------------- */
.report-header {
    display: flex;
    align-items: center;
    gap: 18px;
    background: #ffffff;          /* keep header white */
    border-bottom: 2px solid #001f3f;
    padding: 22px 36px;
}
.report-header img { height: 96px; width: 96px; }
.report-header-text { display: flex; flex-direction: column; gap: 4px; }

.report-header h1 {
    font-size: 22px;
    font-weight: bold;
    letter-spacing: 4px;
    color: #001f3f;
    text-transform: uppercase;
    border: none;
    padding: 0;
    margin: 0;
}
.report-header .subtitle {
    font-size: 11px;
    letter-spacing: 2px;
    color: #555555;
    text-transform: uppercase;
}

/* --------------------------------------------------------------
   Content headings
   -------------------------------------------------------------- */
h1, h2, h3, p { margin: 6px 0; }
h1 {
    font-size: 17px;
    color: #001f3f;
    border-bottom: 1px solid #ccc;
    padding-bottom: 6px;
    margin: 32px 0 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
}
h2 {
    font-size: 14px;
    color: #003366;
    border-left: 3px solid #001f3f;
    padding-left: 10px;
    margin: 24px 0 10px;
    letter-spacing: 1px;
}
h3 {
    font-size: 13px;
    color: #004080;
    margin: 16px 0 6px;
}
p { color: #001f3f; }

/* --------------------------------------------------------------
   Lists
   -------------------------------------------------------------- */
ul { list-style: none; padding-left: 0; margin: 4px 0 10px; }
li {
    padding: 2px 0 2px 14px;
    position: relative;
    color: #001f3f;
}
li::before {
    content: "›";
    position: absolute;
    left: 0;
    color: #001f3f;
}

/* --------------------------------------------------------------
   Links / strong
   -------------------------------------------------------------- */
a   { color: #004080; text-decoration: none; }
a:hover { text-decoration: underline; }
strong { color: #001f3f; }

/* --------------------------------------------------------------
   Table styling – zebra striping
   -------------------------------------------------------------- */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0 18px;
    font-size: 12px;
}
thead tr {
    background: #e0e0e0;          /* light‑gray header */
}
thead th, thead td {
    color: #001f3f;
    font-weight: bold;
    padding: 6px 10px;
    text-align: left;
}
tbody tr:nth-child(even) {
    background: #ffffff;          /* white rows */
}
tbody tr:nth-child(odd) {
    background: #f2f2f2;          /* light‑gray rows */
}
tbody td {
    color: #001f3f;
    padding: 6px 10px;
    vertical-align: top;
}
tbody tr:hover {
    background: #d9d9d9;          /* slightly darker on hover */
}

.executive-summary,
.conclusion {
    margin-top: 2rem;
    padding: 1rem;
    background: #f9f9f9;   /* light gray background */
    border-left: 4px solid #001f3f;  /* navy accent */
}
.executive-summary h2,
.conclusion h2 {
    color: #001f3f;
}
.content {
    max-width: 900px;      /* 800‑1000 px is a good range for a professional look */
    margin: 0 auto;        /* centre the block horizontally */
    padding: 0 20px;       /* optional inner padding */
}
/* --------------------------------------------------------------
   Miscellaneous
   -------------------------------------------------------------- */
hr { border: none; border-top: 1px solid #ccc; margin: 28px 0; }
"""


def _wrap_html_report(title: str, body_md: str, logo_b64: str = "", subtitle: str = "", toc_html: str = "") -> str:
    """
    Convert a markdown report body to a fully self-contained HTML document.
    The logo (if provided as a base64 data URI) is embedded in the page header
    alongside the report title.
    toc_html: optional pre-built table-of-contents block inserted before body.
    """
    escaped_title = html.escape(title)
    logo_tag = (
        f'<img src="{logo_b64}" alt="Draugr logo">'
        if logo_b64 else ""
    )
    sub_tag = (
        f'<span class="subtitle">{html.escape(subtitle)}</span>'
        if subtitle else ""
    )

    body_html = _markdown_body_to_html(body_md)
    toc_block = f'<nav class="toc">{toc_html}</nav>' if toc_html else ""
     # assemble final page
    full_html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>{escaped_title}</title>
        <style>{_REPORT_CSS}
.toc {{
    background: #f0f4f8;
    border: 1px solid #c0ccd8;
    border-radius: 4px;
    padding: 16px 24px;
    margin: 20px 0 32px;
    font-size: 12px;
}}
.toc h2 {{
    font-size: 13px;
    margin-bottom: 10px;
    border-left: none;
    padding-left: 0;
    color: #001f3f;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
.toc ol, .toc ul {{
    padding-left: 20px;
    margin: 0;
}}
.toc > ul > li {{
    list-style: none;
    padding: 2px 0;
}}
.toc > ol > li {{
    list-style: decimal;
    padding: 2px 0;
}}
.toc ul ul > li {{
    list-style: disc;
    margin-left: 4px;
}}
.toc li::before {{
    content: none;
}}
.toc a {{
    color: #004080;
    text-decoration: none;
}}
.toc a:hover {{
    text-decoration: underline;
}}
.back-to-top {{
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: #001f3f;
    color: #ffffff;
    font-size: 11px;
    padding: 6px 12px;
    border-radius: 4px;
    text-decoration: none;
    opacity: 0.75;
    z-index: 999;
}}
.back-to-top:hover {{
    opacity: 1;
}}
.toc-link {{
    float: right;
    font-size: 10px;
    color: #888;
    text-decoration: none;
    font-weight: normal;
    margin-top: 4px;
}}
.toc-link:hover {{
    color: #004080;
}}
</style>
    </head>
    <body>
    <a id="top"></a>
    <a href="#top" class="back-to-top">↑ Top</a>
    <div class="report-header">{logo_tag}<div class="report-header-text"><h1>{escaped_title}</h1>{sub_tag}</div></div>
    <div class="content">
        {toc_block}
        {body_html}
    </div>
    </body>
    </html>"""
    return full_html


# ======================================================================
#  EXECUTIVE REPORT — Business-language risk translation helpers
# ======================================================================

# Maps ATT&CK tactic names to plain-language business impact statements.
_TACTIC_BUSINESS_IMPACT: Dict[str, str] = {
    "initial-access":       "An adversary could gain an initial foothold into the organization's systems, serving as the entry point for further attack activity.",
    "execution":            "An attacker could run malicious commands or software on organizational systems, enabling data theft, disruption, or further compromise.",
    "persistence":          "An attacker could establish a long-term, hidden presence — surviving reboots and password changes — allowing extended undetected access.",
    "privilege-escalation": "An attacker with limited access could elevate their permissions to gain administrative or system-level control, significantly expanding their reach.",
    "defense-evasion":      "An attacker could hide their activity from security monitoring tools, increasing the time before detection and response.",
    "credential-access":    "An attacker could steal account credentials, enabling impersonation of legitimate users and unauthorized access to sensitive systems.",
    "discovery":            "An attacker could map the organization's internal network and identify valuable targets, systems, and data stores.",
    "lateral-movement":     "An attacker could spread from an initially compromised system to other systems across the organization's network.",
    "collection":           "An attacker could identify and gather sensitive organizational data, intellectual property, or operational information.",
    "command-and-control":  "An attacker could establish a covert communication channel to remotely direct compromised systems from outside the organization.",
    "exfiltration":         "An attacker could steal and transmit sensitive data outside the organization, resulting in a data breach.",
    "impact":               "An attacker could disrupt, degrade, or destroy organizational systems and data, causing operational downtime or permanent data loss.",
}

# Maps ATT&CK technique IDs to concise, business-language risk narratives.
_TECHNIQUE_BUSINESS_NARRATIVE: Dict[str, str] = {
    "T1190": "Attackers could exploit weaknesses in internet-facing systems to gain unauthorized remote access without requiring valid credentials — bypassing perimeter defenses entirely.",
    "T1068": "Once inside, attackers could exploit software weaknesses to elevate their access to administrator or system level, giving them full control over affected machines.",
    "T1059": "Attackers could use built-in system tools to run malicious commands — making it difficult to distinguish attack activity from normal operations.",
    "T1203": "Malicious content (files, links, or web pages) could trigger unauthorized code execution on employee workstations, serving as an entry point for broader compromise.",
    "T1078": "Attackers could use stolen or weak credentials to access systems as a legitimate user, making malicious activity harder to detect.",
    "T1499": "Attackers could overwhelm systems with traffic or requests, causing service outages that disrupt operations and deny access to critical capabilities.",
    "T1005": "Attackers could access and collect sensitive files, credentials, and operational data stored on compromised systems.",
    "T1083": "Attackers could enumerate directories and files to identify high-value data targets before exfiltration.",
    "T1105": "Attackers could download additional malicious tools onto compromised systems, expanding their capabilities once inside the network.",
    "T1557": "Attackers could intercept and manipulate communications between systems, enabling credential theft, data tampering, or session hijacking.",
    "T1040": "Attackers could capture unencrypted network traffic to harvest credentials and sensitive data in transit.",
    "T1110": "Attackers could systematically attempt to guess or crack passwords, potentially gaining unauthorized access to accounts without exploiting a specific vulnerability.",
    "T1548": "Attackers could abuse legitimate privilege-management features to bypass security controls and gain elevated system access.",
    "T1222": "Attackers could modify file and directory permissions to gain access to restricted data or maintain persistence after initial compromise.",
    "T1552": "Attackers could locate and harvest stored credentials — including passwords, API keys, and certificates — enabling broader access across the organization.",
    "T1090": "Attackers could route their traffic through internal systems to bypass network monitoring and reach otherwise restricted resources.",
    "T1189": "Employees visiting a compromised website could unknowingly trigger malicious code execution, providing attackers with an initial foothold.",
}

# Maps severity levels and risk scores to plain-language posture descriptions.
def _risk_posture_label(max_score: float, crit: int, kev: int, expl: int) -> str:
    """Return a plain-language risk posture label suitable for executive reporting."""
    if kev > 0 or max_score >= 80:
        return "CRITICAL — Immediate action required. Active exploitation is occurring or imminent."
    if expl > 0 or max_score >= 60 or crit > 0:
        return "HIGH — Significant risk. Exploitation tools exist and attack probability is elevated."
    if max_score >= 40:
        return "MODERATE — Meaningful exposure. Vulnerabilities present but exploitation is less immediate."
    return "LOW — Limited near-term risk. Standard patching cadence is appropriate."


def _technique_to_business(aid: str, tactic_list: List[str]) -> str:
    """Return the best available business-language description for a technique."""
    narrative = _TECHNIQUE_BUSINESS_NARRATIVE.get(aid)
    if narrative:
        return narrative
    # Fall back to tactic-level impact
    for tactic in tactic_list:
        t = tactic.lower().replace(" ", "-")
        impact = _TACTIC_BUSINESS_IMPACT.get(t)
        if impact:
            return impact
    return "Attackers could exploit this weakness to gain unauthorized access, disrupt operations, or compromise sensitive data."


def _attack_scenario_business(rows: List[Dict[str, Any]], software_name: str) -> List[str]:
    """
    Generate 1–3 concise, business-language attack scenario paragraphs
    for a software item, based on its ATT&CK technique mappings.
    Returns a list of scenario strings.
    """
    # Collect unique technique IDs and their tactic sets, prioritised by risk score
    seen_aids: set = set()
    ordered_attacks: List[Tuple[str, str, List[str]]] = []  # (aid, name, tactics)
    for r in rows:
        attacks = _split_multi(r.get("ATT&CK Techniques", ""))
        tactics = _split_multi(r.get("ATT&CK Tactics", ""))
        for atk in attacks:
            m = re.match(r"^([A-Z0-9.]+)\s*\((.*?)\)$", atk)
            if m:
                aid, aname = m.group(1), m.group(2)
            else:
                aid, aname = atk, atk
            if aid and aid not in seen_aids:
                seen_aids.add(aid)
                ordered_attacks.append((aid, aname, tactics))

    scenarios: List[str] = []
    for aid, aname, tactics in ordered_attacks[:3]:
        narrative = _technique_to_business(aid, tactics)
        scenarios.append(narrative)
    return scenarios


def _kev_business_statement(kev_count: int, sw_name: str) -> str:
    if kev_count == 0:
        return ""
    if kev_count == 1:
        return (
            f"One vulnerability affecting **{sw_name}** has been confirmed as actively "
            "exploited by threat actors in real-world attacks. The U.S. Cybersecurity and "
            "Infrastructure Security Agency (CISA) has mandated remediation of this class "
            "of vulnerability for federal agencies, reflecting the severity of the threat."
        )
    return (
        f"**{kev_count} vulnerabilities** affecting **{sw_name}** have been confirmed as "
        "actively exploited by threat actors in real-world attacks. These represent the "
        "highest-priority remediation items — CISA has mandated patching of such "
        "vulnerabilities for all federal agencies due to the documented exploitation activity."
    )


def _exploit_business_statement(expl_count: int, sw_name: str) -> str:
    if expl_count == 0:
        return ""
    if expl_count == 1:
        return (
            f"Publicly available exploit code exists for one vulnerability in **{sw_name}**. "
            "This lowers the technical skill required to mount an attack, increasing the "
            "likelihood of exploitation by less sophisticated threat actors."
        )
    return (
        f"Publicly available exploit code exists for **{expl_count} vulnerabilities** in "
        f"**{sw_name}**. This significantly lowers the barrier to attack — these "
        "vulnerabilities can be exploited by a wide range of threat actors with minimal "
        "technical expertise."
    )


# Business-language remediation actions keyed to ATT&CK technique IDs.
_TECHNIQUE_REMEDIATION: Dict[str, str] = {
    "T1190": "Apply vendor security patches to all internet-accessible systems and review network access controls to limit unnecessary external exposure.",
    "T1068": "Deploy vendor patches to eliminate the privilege-escalation pathway and enforce the principle of least privilege across all accounts.",
    "T1059": "Restrict which users and processes can run system commands, and deploy endpoint protection capable of detecting anomalous command execution.",
    "T1203": "Apply vendor patches and ensure endpoint protection is active on all workstations; consider email and web content filtering.",
    "T1078": "Enforce multi-factor authentication on all systems, rotate compromised credentials, and audit account access regularly.",
    "T1499": "Deploy availability protections such as rate limiting and redundancy, and apply vendor patches to eliminate the underlying weakness.",
    "T1005": "Apply patches, enforce data-access controls, and ensure sensitive data is encrypted at rest.",
    "T1557": "Enforce encrypted communications (TLS) across all internal and external systems and deploy network monitoring.",
    "T1040": "Enforce encryption for all data in transit and segment the network to limit the scope of any interception.",
    "T1110": "Enforce strong password policies, implement account-lockout controls, and deploy multi-factor authentication.",
    "T1548": "Apply patches, enforce least-privilege access, and audit privileged-account activity.",
    "T1552": "Rotate all stored credentials, move secrets to a dedicated vault solution, and scan for hardcoded credentials in codebases.",
}


# ── SVG graphic helpers ────────────────────────────────────────────────────

def _svg_donut(sev_counts: Dict[str, int], total: int) -> str:
    """
    Inline SVG donut chart — severity breakdown.
    Segments: CRITICAL (red) / HIGH (orange) / MEDIUM (amber) / LOW (green).
    Total CVE count displayed in the centre.
    """
    colours = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#d35400",
        "MEDIUM":   "#d4ac0d",
        "LOW":      "#27ae60",
        "INFO":     "#7f8c8d",
        "OTHER":    "#95a5a6",
    }
    labels  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OTHER"]
    counts  = [sev_counts.get(l, 0) for l in labels]
    total_s = sum(counts)
    if total_s == 0:
        return ""

    cx, cy, r_out, r_in = 110, 110, 90, 54
    import math

    def arc_path(start_deg: float, end_deg: float) -> str:
        s = math.radians(start_deg - 90)
        e = math.radians(end_deg   - 90)
        large = 1 if (end_deg - start_deg) > 180 else 0
        x1o = cx + r_out * math.cos(s);  y1o = cy + r_out * math.sin(s)
        x2o = cx + r_out * math.cos(e);  y2o = cy + r_out * math.sin(e)
        x1i = cx + r_in  * math.cos(e);  y1i = cy + r_in  * math.sin(e)
        x2i = cx + r_in  * math.cos(s);  y2i = cy + r_in  * math.sin(s)
        return (f"M {x1o:.2f} {y1o:.2f} "
                f"A {r_out} {r_out} 0 {large} 1 {x2o:.2f} {y2o:.2f} "
                f"L {x1i:.2f} {y1i:.2f} "
                f"A {r_in} {r_in} 0 {large} 0 {x2i:.2f} {y2i:.2f} Z")

    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="320" height="220" '
             'style="font-family:Segoe UI,sans-serif;display:block;margin:16px auto;">']

    # Draw segments
    angle = 0.0
    for label, count in zip(labels, counts):
        if count == 0:
            continue
        sweep = (count / total_s) * 360
        # Avoid full-circle degenerate arc
        end = angle + sweep - 0.01 if sweep >= 360 else angle + sweep
        parts.append(f'<path d="{arc_path(angle, end)}" fill="{colours[label]}" '
                     f'stroke="#fff" stroke-width="2"/>')
        angle += sweep

    # Centre text
    parts += [
        f'<text x="{cx}" y="{cy - 8}" text-anchor="middle" '
        f'font-size="26" font-weight="700" fill="#1a1a2e">{total_s}</text>',
        f'<text x="{cx}" y="{cy + 12}" text-anchor="middle" '
        f'font-size="11" fill="#555">Total CVEs</text>',
    ]

    # Legend (right side)
    lx, ly = 218, 60
    for i, (label, count) in enumerate(zip(labels, counts)):
        y = ly + i * 26
        pct = f"{count/total_s*100:.0f}%" if total_s else "0%"
        parts += [
            f'<rect x="{lx}" y="{y}" width="13" height="13" '
            f'fill="{colours[label]}" rx="2"/>',
            f'<text x="{lx+18}" y="{y+11}" font-size="11" fill="#333">'
            f'{label}  <tspan font-weight="700">{count}</tspan>'
            f'  <tspan fill="#888">({pct})</tspan></text>',
        ]

    parts.append('</svg>')
    return "\n".join(parts)


def _svg_risk_matrix(
    grouped: Dict[Any, List[Dict[str, Any]]],
) -> str:
    """
    Inline SVG 5×5 likelihood vs impact risk matrix.
    Each software item is plotted as a labelled dot.
    Legend sits below the chart to avoid overlapping dots.
    """
    import math

    W, H    = 500, 420   # extra height for below-chart legend
    PAD_L   = 76
    PAD_B   = 50
    PAD_T   = 30
    PAD_R   = 20
    LEGEND_H = 90        # reserved at bottom for legend
    GRID    = 5
    CW      = (W - PAD_L - PAD_R) / GRID
    CH      = (H - PAD_T - PAD_B - LEGEND_H) / GRID
    PLOT_H  = H - PAD_T - PAD_B - LEGEND_H

    zone_colours = [
        "#27ae6022", "#27ae6033", "#f39c1233", "#e74c3c33", "#c0392b44",
        "#27ae6033", "#f39c1233", "#f39c1233", "#e74c3c44", "#c0392b55",
        "#f39c1233", "#f39c1233", "#e74c3c33", "#e74c3c44", "#c0392b55",
        "#e74c3c33", "#e74c3c44", "#e74c3c44", "#c0392b55", "#c0392b66",
        "#e74c3c44", "#c0392b44", "#c0392b55", "#c0392b66", "#c0392b77",
    ]

    def _likelihood(rows: List[Dict[str, Any]]) -> float:
        kev  = any(str(r.get("Known Exploited Vulnerability","")).upper()=="YES" for r in rows)
        expl = any(str(r.get("Public Exploit","")).upper()=="YES" for r in rows)
        epss = max((_epss_float(r.get("EPSS Score",0)) for r in rows), default=0.0)
        score = 0.0
        if kev:  score += 4.0
        elif expl: score += 2.5
        score += min(epss * 3.0, 1.5)
        return min(score, 5.0)

    def _impact(rows: List[Dict[str, Any]]) -> float:
        crit = any(str(r.get("CVSS Severity","")).upper()=="CRITICAL" for r in rows)
        high = any(str(r.get("CVSS Severity","")).upper()=="HIGH"     for r in rows)
        max_rs = max((_to_float(r.get("Risk Score",0)) for r in rows), default=0.0)
        base = 5.0 if crit else 3.5 if high else 2.0
        return min(base + max_rs / 50.0, 5.0)

    def _px(likelihood: float, impact: float):
        x = PAD_L + (likelihood / 5.0) * (W - PAD_L - PAD_R)
        y = PAD_T + PLOT_H - (impact / 5.0) * PLOT_H
        return x, y

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'style="font-family:Segoe UI,sans-serif;display:block;margin:16px auto;'
        f'border:1px solid #ddd;border-radius:6px;background:#fafafa;">',
    ]

    # Colour zones
    for row in range(GRID):
        for col in range(GRID):
            idx = (GRID - 1 - row) * GRID + col
            x   = PAD_L + col * CW
            y   = PAD_T + row * CH
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{CW:.1f}" height="{CH:.1f}" '
                         f'fill="{zone_colours[idx]}" stroke="#ccc" stroke-width="0.5"/>')

    # Axis labels
    axis_style = 'font-size="10" fill="#555" text-anchor="middle"'
    x_labels = ["Very Low", "Low", "Moderate", "High", "Very High"]
    y_labels = ["Very Low", "Low", "Moderate", "High", "Critical"]
    for i, lbl in enumerate(x_labels):
        x = PAD_L + (i + 0.5) * CW
        parts.append(f'<text x="{x:.1f}" y="{PAD_T + PLOT_H + 16}" {axis_style}>{lbl}</text>')
    for i, lbl in enumerate(y_labels):
        y = PAD_T + PLOT_H - (i + 0.5) * CH
        parts.append(f'<text x="{PAD_L - 14}" y="{y:.1f}" font-size="10" fill="#555" '
                     f'text-anchor="end" dominant-baseline="middle">{lbl}</text>')

    # Axis titles
    parts += [
        f'<text x="{PAD_L + (W-PAD_L-PAD_R)/2:.1f}" y="{PAD_T + PLOT_H + 34}" '
        f'font-size="11" fill="#333" text-anchor="middle" font-weight="600">LIKELIHOOD</text>',
        f'<text x="12" y="{PAD_T + PLOT_H/2:.1f}" '
        f'font-size="11" fill="#333" text-anchor="middle" font-weight="600" '
        f'transform="rotate(-90,12,{PAD_T+PLOT_H/2:.1f})">IMPACT</text>',
    ]

    # Plot software dots
    dot_colours = ["#c0392b","#8e44ad","#2980b9","#16a085","#d35400",
                   "#27ae60","#f39c12","#1abc9c","#2c3e50","#7f8c8d"]
    plotted: List[tuple] = []
    for idx, ((sw_name, sw_ver), sw_rows) in enumerate(
        sorted(grouped.items(), key=lambda kv: (
            -max((_to_float(r.get("Risk Score",0)) for r in kv[1]), default=0)
        ))
    ):
        lik  = _likelihood(sw_rows)
        con  = _impact(sw_rows)
        px, py = _px(lik, con)
        colour  = dot_colours[idx % len(dot_colours)]
        label   = sw_name[:22] + ("…" if len(sw_name) > 22 else "")
        num     = idx + 1
        plotted.append((colour, label, num))
        parts.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="10" '
                     f'fill="{colour}" fill-opacity="0.85" stroke="#fff" stroke-width="1.5"/>')
        parts.append(f'<text x="{px:.1f}" y="{py+4:.1f}" text-anchor="middle" '
                     f'font-size="9" font-weight="700" fill="#fff">{num}</text>')

    # Legend below the plot area — two columns
    if plotted:
        legend_y = PAD_T + PLOT_H + 48
        col_w    = (W - PAD_L) // 2
        for i, (colour, label, num) in enumerate(plotted):
            col  = i % 2
            row  = i // 2
            lx   = PAD_L + col * col_w
            ly   = legend_y + row * 16
            parts += [
                f'<circle cx="{lx+6}" cy="{ly:.1f}" r="5" fill="{colour}"/>',
                f'<text x="{lx+15}" y="{ly+4:.1f}" font-size="9" fill="#333">'
                f'<tspan font-weight="700">{num}.</tspan> {html.escape(label)}</text>',
            ]

    parts.append('</svg>')
    return "\n".join(parts)


def _svg_controls_heatmap(
    all_rows: List[Dict[str, Any]],
    grouped: Dict[Any, List[Dict[str, Any]]],
    top_n: int = 10,
) -> str:
    """
    Controls gap heatmap for the executive report.
    Rows = top NIST 800-53 controls by frequency.
    Columns = software items.
    Cell colour = number of CVEs on that software missing that control.
    """
    from collections import Counter as _Counter

    # Count control frequency per software item
    sw_names = sorted({n for (n, _) in grouped.keys() if n},
                      key=lambda s: -max(
                          (_to_float(r.get("Risk Score", 0))
                           for r in grouped.get((s, next(
                               (v for (n, v) in grouped if n == s), "")), [])),
                          default=0
                      ))[:12]

    # Global top controls by total frequency
    global_counter: Counter = Counter()
    for r in all_rows:
        for ctrl in _split_multi(r.get("NIST 800-53 Controls", "")):
            cid = ctrl.split()[0] if ctrl.split() else ctrl
            if cid:
                global_counter[cid] += 1
    top_controls = [c for c, _ in global_counter.most_common(top_n)]

    if not top_controls or not sw_names:
        return ""

    # Per-software per-control counts
    sw_ctrl_counts: Dict[str, Dict[str, int]] = {s: {} for s in sw_names}
    for (sw_name, _), rows in grouped.items():
        if sw_name not in sw_ctrl_counts:
            continue
        for r in rows:
            for ctrl in _split_multi(r.get("NIST 800-53 Controls", "")):
                cid = ctrl.split()[0] if ctrl.split() else ctrl
                if cid in top_controls:
                    sw_ctrl_counts[sw_name][cid] = sw_ctrl_counts[sw_name].get(cid, 0) + 1

    max_count = max(
        (v for d in sw_ctrl_counts.values() for v in d.values()),
        default=1
    ) or 1

    CELL_W  = max(52, min(80, int(520 / len(sw_names))))
    CELL_H  = 26
    PAD_L   = 72
    PAD_T   = 80
    W       = PAD_L + CELL_W * len(sw_names) + 20
    H       = PAD_T + CELL_H * len(top_controls) + 50

    def _heat_colour(count: int) -> str:
        if count == 0:
            return "#f0f0f0"
        intensity = min(count / max_count, 1.0)
        # White → deep red
        r = 255
        g = int(255 * (1 - intensity * 0.85))
        b = int(255 * (1 - intensity * 0.85))
        return f"#{r:02x}{g:02x}{b:02x}"

    def _text_colour(count: int) -> str:
        if count == 0:
            return "#aaa"
        intensity = min(count / max_count, 1.0)
        return "#fff" if intensity > 0.5 else "#333"

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'style="font-family:Segoe UI,sans-serif;display:block;margin:16px auto;overflow:visible;">',
    ]

    # Column headers — rotated software names
    for ci, sw in enumerate(sw_names):
        x = PAD_L + ci * CELL_W + CELL_W // 2
        y = PAD_T - 8
        label = sw[:14] + ("…" if len(sw) > 14 else "")
        parts.append(
            f'<text x="{x}" y="{y}" font-size="9" fill="#333" text-anchor="start" '
            f'transform="rotate(-40,{x},{y})">{html.escape(label)}</text>'
        )

    # Rows
    for ri, ctrl in enumerate(top_controls):
        y = PAD_T + ri * CELL_H
        short = _NIST_IMPL.get(ctrl, "").split("—")[0].strip()[:28]
        label = f"{ctrl}" + (f" – {short}" if short else "")

        # Row label
        parts.append(
            f'<text x="{PAD_L - 4}" y="{y + CELL_H - 7}" text-anchor="end" '
            f'font-size="9" fill="#333" font-weight="600">{html.escape(ctrl)}</text>'
        )

        # Cells
        for ci, sw in enumerate(sw_names):
            x     = PAD_L + ci * CELL_W
            count = sw_ctrl_counts.get(sw, {}).get(ctrl, 0)
            fill  = _heat_colour(count)
            tcol  = _text_colour(count)
            parts.append(
                f'<rect x="{x}" y="{y}" width="{CELL_W-1}" height="{CELL_H-1}" '
                f'fill="{fill}" rx="2" stroke="#e0e0e0" stroke-width="0.5"/>'
            )
            if count > 0:
                parts.append(
                    f'<text x="{x+CELL_W//2}" y="{y+CELL_H-8}" text-anchor="middle" '
                    f'font-size="9" font-weight="700" fill="{tcol}">{count}</text>'
                )

    # Colour scale legend
    ly = H - 30
    parts.append(f'<text x="{PAD_L}" y="{ly - 4}" font-size="9" fill="#555">Gap severity:</text>')
    scale_steps = 5
    sw = 20
    for i in range(scale_steps):
        intensity = i / (scale_steps - 1)
        count_approx = int(intensity * max_count)
        fill = _heat_colour(count_approx)
        lx = PAD_L + 80 + i * (sw + 4)
        parts += [
            f'<rect x="{lx}" y="{ly - 12}" width="{sw}" height="14" fill="{fill}" rx="2" '
            f'stroke="#ccc" stroke-width="0.5"/>',
        ]
    parts += [
        f'<text x="{PAD_L + 80}" y="{ly + 6}" font-size="8" fill="#888" text-anchor="middle">Low</text>',
        f'<text x="{PAD_L + 80 + (scale_steps-1)*(sw+4)}" y="{ly + 6}" font-size="8" '
        f'fill="#888" text-anchor="middle">High</text>',
        f'<text x="{PAD_L + 80 + (scale_steps+1)*(sw+4)}" y="{ly - 2}" font-size="8" '
        f'fill="#aaa">Numbers = CVE count missing this control</text>',
    ]

    parts.append('</svg>')
    return "\n".join(parts)


def _svg_bar_chart(
    grouped: Dict[Any, List[Dict[str, Any]]],
    top_n: int = 10,
) -> str:
    """
    Horizontal bar chart — top N software items ranked by max risk score.
    Bars are colour-coded by highest severity found in that software.
    """
    sev_colour = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#d35400",
        "MEDIUM":   "#d4ac0d",
        "LOW":      "#27ae60",
    }

    # Build ranked list
    ranked = []
    for (sw_name, sw_ver), rows in grouped.items():
        max_rs = max((_to_float(r.get("Risk Score", 0)) for r in rows), default=0.0)
        sevs   = [str(r.get("CVSS Severity","")).upper() for r in rows]
        top_sev = ("CRITICAL" if "CRITICAL" in sevs else
                   "HIGH"     if "HIGH"     in sevs else
                   "MEDIUM"   if "MEDIUM"   in sevs else "LOW")
        kev    = any(str(r.get("Known Exploited Vulnerability","")).upper()=="YES" for r in rows)
        ranked.append((sw_name, sw_ver, max_rs, top_sev, kev))
    ranked.sort(key=lambda x: x[2], reverse=True)
    ranked = ranked[:top_n]
    if not ranked:
        return ""

    BAR_H   = 28
    PAD_L   = 190
    PAD_R   = 60
    PAD_T   = 30
    PAD_B   = 20
    W       = 600
    H       = PAD_T + len(ranked) * (BAR_H + 6) + PAD_B
    MAX_BAR = W - PAD_L - PAD_R
    max_score = max(r[2] for r in ranked) or 1.0

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'style="font-family:Segoe UI,sans-serif;display:block;margin:16px auto;">',
        f'<text x="{W//2}" y="18" text-anchor="middle" font-size="12" '
        f'font-weight="600" fill="#1a1a2e">Top {len(ranked)} Systems by Risk Score</text>',
    ]

    for i, (sw_name, sw_ver, score, sev, kev) in enumerate(ranked):
        y      = PAD_T + i * (BAR_H + 6)
        bar_w  = max(4.0, (score / max_score) * MAX_BAR)
        colour = sev_colour.get(sev, "#888")
        label  = f"{sw_name[:26]}{'…' if len(sw_name)>26 else ''}"
        kev_tag = " ⚠KEV" if kev else ""

        # Background row
        parts.append(f'<rect x="{PAD_L}" y="{y}" width="{MAX_BAR}" height="{BAR_H}" '
                     f'fill="#f0f0f0" rx="4"/>')
        # Filled bar
        parts.append(f'<rect x="{PAD_L}" y="{y}" width="{bar_w:.1f}" height="{BAR_H}" '
                     f'fill="{colour}" rx="4" fill-opacity="0.85"/>')
        # Software name (left)
        parts.append(f'<text x="{PAD_L-6}" y="{y + BAR_H//2 + 4}" text-anchor="end" '
                     f'font-size="11" fill="#222">{html.escape(label)}</text>')
        # Score label (right of bar)
        parts.append(f'<text x="{PAD_L + bar_w + 5:.1f}" y="{y + BAR_H//2 + 4}" '
                     f'font-size="10" fill="{colour}" font-weight="700">'
                     f'{score:.1f}{html.escape(kev_tag)}</text>')

    parts.append('</svg>')
    return "\n".join(parts)


def _svg_cve_heatmap(
    grouped: Dict[Any, List[Dict[str, Any]]],
    max_sw: int = 15,
    max_cves: int = 20,
) -> str:
    """
    CVE × Software severity heatmap for the technical report.
    Rows = top CVEs (by risk score), Columns = software items.
    Cell colour = severity of that CVE on that software (grey = not applicable).
    """
    sev_fill = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#d35400",
        "MEDIUM":   "#d4ac0d",
        "LOW":      "#27ae60",
        "":         "#ececec",
    }

    # Build CVE → software → severity lookup
    cve_sw_map: Dict[str, Dict[str, str]] = {}
    for (sw_name, _sw_ver), rows in grouped.items():
        for r in rows:
            cve = str(r.get("CVE ID","")).strip()
            sev = str(r.get("CVSS Severity","")).upper()
            if cve:
                if cve not in cve_sw_map:
                    cve_sw_map[cve] = {}
                cve_sw_map[cve][sw_name] = sev

    # Top CVEs by max risk score across all software
    cve_scores: Dict[str, float] = {}
    for r in (r for rows in grouped.values() for r in rows):
        cve = str(r.get("CVE ID","")).strip()
        rs  = _to_float(r.get("Risk Score",0))
        if cve and rs > cve_scores.get(cve, 0):
            cve_scores[cve] = rs
    top_cves = [c for c, _ in sorted(cve_scores.items(), key=lambda x:-x[1])][:max_cves]

    # Top software by max risk score
    sw_scores = {
        sw_name: max((_to_float(r.get("Risk Score",0)) for r in rows), default=0)
        for (sw_name, _), rows in grouped.items()
    }
    top_sw = [s for s, _ in sorted(sw_scores.items(), key=lambda x:-x[1])][:max_sw]

    if not top_cves or not top_sw:
        return ""

    CELL_W  = max(60, min(90, int(560 / len(top_sw))))
    CELL_H  = 22
    PAD_L   = 130
    PAD_T   = 90
    W       = PAD_L + CELL_W * len(top_sw) + 20
    H       = PAD_T + CELL_H * len(top_cves) + 40

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'style="font-family:Segoe UI,sans-serif;display:block;margin:16px auto;'
        f'overflow:visible;">',
    ]

    # Column headers (software names — rotated)
    for ci, sw in enumerate(top_sw):
        x = PAD_L + ci * CELL_W + CELL_W // 2
        y = PAD_T - 8
        label = sw[:16] + ("…" if len(sw) > 16 else "")
        parts.append(
            f'<text x="{x}" y="{y}" font-size="9" fill="#333" text-anchor="start" '
            f'transform="rotate(-45,{x},{y})">{html.escape(label)}</text>'
        )

    # Rows
    for ri, cve in enumerate(top_cves):
        y = PAD_T + ri * CELL_H
        # Row label
        parts.append(
            f'<text x="{PAD_L - 6}" y="{y + CELL_H - 6}" text-anchor="end" '
            f'font-size="9" fill="#333">{html.escape(cve)}</text>'
        )
        # Cells
        for ci, sw in enumerate(top_sw):
            x   = PAD_L + ci * CELL_W
            sev = cve_sw_map.get(cve, {}).get(sw, "")
            fill = sev_fill.get(sev, sev_fill[""])
            parts.append(
                f'<rect x="{x}" y="{y}" width="{CELL_W-1}" height="{CELL_H-1}" '
                f'fill="{fill}" rx="2"/>'
            )
            if sev:
                abbr = sev[0]  # C / H / M / L
                parts.append(
                    f'<text x="{x+CELL_W//2}" y="{y+CELL_H-6}" text-anchor="middle" '
                    f'font-size="8" font-weight="700" fill="white">{abbr}</text>'
                )

    # Legend
    lx = PAD_L
    ly = H - 28
    for sev, colour in [("CRITICAL","#c0392b"),("HIGH","#d35400"),
                         ("MEDIUM","#d4ac0d"),("LOW","#27ae60"),("N/A","#ececec")]:
        parts.append(f'<rect x="{lx}" y="{ly}" width="12" height="12" fill="{colour}" rx="2"/>')
        parts.append(f'<text x="{lx+15}" y="{ly+10}" font-size="9" fill="#555">{sev}</text>')
        lx += 75

    parts.append('</svg>')
    return "\n".join(parts)


def build_executive_report_markdown(
    all_rows: List[Dict[str, Any]],
    report_title: str = "Executive Cyber Risk Brief",
    otx_results: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Board-ready Executive Cyber Risk Brief.

    Audience: Executives, board members, program/acquisition/operational leadership,
              and non-technical stakeholders.

    Structure:
      1. Executive Summary — overall posture, key decisions required
      2. Overall Risk Posture — likelihood vs consequence heat map narrative
      3. Most Critical Risks — business-language description per software
      4. Attack Scenarios — what an adversary would actually do
      5. Operational & Business Impacts — mission, financial, regulatory, reputational
      6. Risk Trends — active exploitation activity
      7. Strategic Recommendations — leadership decisions
      8. Resource Implications — investment framing
      9. Prioritized Remediation Roadmap — tiered action plan
     10. Residual Organizational Risk — what remains after remediation
    """
    import datetime

    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        key = (str(row.get("Software Name", "")).strip(), str(row.get("Software Version", "")).strip())
        grouped[key].append(row)
    otx_results = otx_results or {}
    scan_date = datetime.datetime.now().strftime("%B %d, %Y")

    # ── Aggregate stats ──────────────────────────────────────────────────
    total_cves   = len(all_rows)
    sev_counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
    for r in all_rows:
        sev = str(r.get("CVSS Severity", "") or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["OTHER"] += 1
    kev_total    = sum(1 for r in all_rows if str(r.get("Known Exploited Vulnerability", "")).upper() == "YES")
    expl_total   = sum(1 for r in all_rows if str(r.get("Public Exploit", "")).upper() == "YES")
    confirmed_total = sum(1 for r in all_rows if str(r.get("Version Confirmed", "")).upper() == "YES")
    max_risk     = max((_to_float(r.get("Risk Score", 0)) for r in all_rows), default=0.0)
    sw_count     = len(grouped)
    sw_names     = sorted({n for (n, _) in grouped.keys() if n})
    top5         = _top_techniques(all_rows, top_n=5)

    # Active GreyNoise exploitation count
    gn_active_total = sum(
        1 for r in all_rows
        if _THREAT_INTEL_CACHE.get(r.get("CVE ID", ""), {}).get("greynoise", {}).get("noise")
    )

    # Overall posture
    posture = _risk_posture_label(max_risk, sev_counts["CRITICAL"], kev_total, expl_total)

    # ── TOC ──────────────────────────────────────────────────────────────
    toc_html = (
        '<h2>Contents</h2><ol>'
        '<li><a href="#executive-summary">Executive Summary</a></li>'
        '<li><a href="#overall-risk-posture">Overall Risk Posture</a></li>'
        '<li><a href="#most-critical-risks">Most Critical Risks</a></li>'
        '<li><a href="#attack-scenarios">Attack Scenarios</a></li>'
        '<li><a href="#operational-and-business-impacts">Operational and Business Impacts</a></li>'
        '<li><a href="#risk-trends">Risk Trends</a></li>'
        '<li><a href="#strategic-recommendations">Strategic Recommendations</a></li>'
        '<li><a href="#resource-implications">Resource Implications</a></li>'
        '<li><a href="#prioritized-remediation-roadmap">Prioritized Remediation Roadmap</a></li>'
        '<li><a href="#residual-organizational-risk">Residual Organizational Risk</a></li>'
        '</ol>'
    )

    lines: List[str] = []

    # ── SECTION 1 — EXECUTIVE SUMMARY ───────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
        f"**Assessment Date:** {scan_date}  |  "
        f"**Systems Reviewed:** {sw_count}  |  "
        f"**Overall Risk Posture:** {posture.split('—')[0].strip()}",
        "",
    ]

    # Determine urgency framing
    if kev_total > 0:
        urgency_lead = (
            f"This assessment identified **{kev_total} actively exploited "
            f"{'vulnerability' if kev_total == 1 else 'vulnerabilities'}** across the "
            f"reviewed systems. Threat actors are currently exploiting these weaknesses in "
            f"real-world attacks against organizations worldwide. Immediate leadership "
            f"action is required."
        )
    elif sev_counts["CRITICAL"] > 0 or expl_total > 0:
        urgency_lead = (
            f"This assessment identified **{sev_counts['CRITICAL']} critical-severity "
            f"{'weakness' if sev_counts['CRITICAL'] == 1 else 'weaknesses'}** with "
            f"{expl_total} publicly available attack tools, across {sw_count} reviewed "
            f"systems. The probability of exploitation is elevated and prompt action is warranted."
        )
    else:
        urgency_lead = (
            f"This assessment reviewed {sw_count} systems and identified "
            f"{total_cves} security weaknesses requiring attention as part of a structured "
            f"remediation programme."
        )
    lines += [urgency_lead, ""]

    # Severity donut chart
    _donut_svg = _svg_donut(sev_counts, total_cves)
    if _donut_svg:
        lines += ["<div style='text-align:center;margin:20px 0;'>",
                  _donut_svg, "</div>", ""]

    # Decision summary box
    lines += [
        "**Leadership decisions required:**",
        "",
    ]
    if kev_total > 0:
        lines.append(f"- **Authorize emergency patching** for {kev_total} actively exploited {'system' if kev_total == 1 else 'systems'} — within 24–72 hours.")
    if sev_counts["CRITICAL"] > 0:
        lines.append(f"- **Direct IT/Security** to prioritize remediation of {sev_counts['CRITICAL']} critical-severity weaknesses within the current sprint/cycle.")
    if expl_total > 0:
        lines.append(f"- **Confirm monitoring is active** on systems with publicly available attack tools ({expl_total} {'instance' if expl_total == 1 else 'instances'}).")
    lines += [
        "- **Review and approve** the remediation roadmap in Section 9.",
        "- **Confirm resources** (personnel and budget) are allocated to address findings.",
        "",
        "---",
        "",
    ]

    # ── SECTION 2 — OVERALL RISK POSTURE ────────────────────────────────
    lines += [
        "## Overall Risk Posture",
        "",
        f"**{posture}**",
        "",
    ]

    # Narrative posture paragraph
    if kev_total > 0 or gn_active_total > 0:
        lines.append(
            f"The organization's current exposure is **elevated above baseline**. "
            f"{'Active real-world exploitation of identified weaknesses has been confirmed. ' if kev_total > 0 else ''}"
            f"{'Threat monitoring services have detected ongoing exploitation attempts targeting these specific vulnerabilities. ' if gn_active_total > 0 else ''}"
            "The likelihood of a successful attack is high if remediation action is not taken promptly."
        )
    elif sev_counts["CRITICAL"] > 0 and expl_total > 0:
        lines.append(
            "The organization faces a **high-probability, high-consequence** threat scenario. "
            "Critical weaknesses exist alongside publicly available attack tools, meaning "
            "adversaries do not require advanced capabilities to mount a successful attack. "
            "The window of opportunity for remediation before exploitation is narrow."
        )
    elif sev_counts["CRITICAL"] > 0:
        lines.append(
            "The organization has critical weaknesses that, if exploited, could result in "
            "significant operational disruption or data loss. While no confirmed active "
            "exploitation has been detected for these specific systems, the severity of the "
            "weaknesses warrants prioritized attention."
        )
    else:
        lines.append(
            "The organization's current exposure is within a manageable range. "
            "Identified weaknesses should be addressed through a structured remediation "
            "programme to maintain a strong defensive posture."
        )
    lines.append("")

    # Risk posture table
    lines += [
        "| Risk Dimension | Status | Assessment |",
        "|---|---|---|",
        f"| Active exploitation confirmed | {'⚠ YES' if kev_total > 0 else 'No'} | {'Immediate action required' if kev_total > 0 else 'No confirmed active exploitation at this time'} |",
        f"| Attack tools publicly available | {'⚠ YES' if expl_total > 0 else 'No'} | {f'{expl_total} weaknesses have known, accessible attack tools' if expl_total > 0 else 'No publicly available attack tools identified'} |",
        f"| Critical-severity weaknesses | {'⚠ YES' if sev_counts['CRITICAL'] > 0 else 'No'} | {str(sev_counts['CRITICAL']) + ' critical findings requiring priority attention' if sev_counts['CRITICAL'] > 0 else 'No critical findings'} |",
        f"| Threat actor interest | {'⚠ Elevated' if gn_active_total > 0 else 'Standard'} | {'Active scanning and exploitation attempts observed' if gn_active_total > 0 else 'No anomalous threat activity detected'} |",
        f"| Regulatory/compliance exposure | {'⚠ YES' if kev_total > 0 else 'Potential'} | {'KEV-listed vulnerabilities carry federal remediation mandates' if kev_total > 0 else 'Unpatched critical findings may create compliance gaps'} |",
        "",
    ]

    # Likelihood vs Consequence risk matrix
    _matrix_svg = _svg_risk_matrix(grouped)
    if _matrix_svg:
        lines += [
            "<div style='text-align:center;margin:20px 0;'>",
            "<p style='font-size:12px;color:#555;margin-bottom:4px;'>"
            "<em>Figure: Likelihood vs Consequence — each numbered dot represents a software component. "
            "Upper-right quadrant (red) = highest priority.</em></p>",
            _matrix_svg,
            "</div>",
            "",
        ]

    # Controls gap heatmap
    _controls_svg = _svg_controls_heatmap(all_rows, grouped)
    if _controls_svg:
        lines += [
            "<div style='overflow-x:auto;margin:20px 0;'>",
            "<p style='font-size:12px;color:#555;margin-bottom:4px;'>"
            "<em>Figure: Security control gap heatmap — darker cells indicate more CVEs "
            "mapping to a missing control on that system. Prioritize controls in the "
            "darkest cells.</em></p>",
            _controls_svg,
            "</div>",
            "",
        ]

    lines += ["---", ""]

    # ── SECTION 3 — MOST CRITICAL RISKS ─────────────────────────────────
    lines += [
        "## Most Critical Risks",
        "",
        "The following systems represent the highest-priority risk to the organization. "
        "Each entry describes the nature of the risk in operational terms.",
        "",
    ]

    # Top software bar chart
    _bar_svg = _svg_bar_chart(grouped)
    if _bar_svg:
        lines += [
            "<div style='text-align:center;margin:20px 0;'>",
            "<p style='font-size:12px;color:#555;margin-bottom:4px;'>"
            "<em>Figure: Systems ranked by maximum risk score. ⚠KEV = actively exploited.</em></p>",
            _bar_svg,
            "</div>",
            "",
        ]

    # Rank software by criticality
    sw_ranked = sorted(
        grouped.items(),
        key=lambda kv: (
            sum(1 for r in kv[1] if str(r.get("Known Exploited Vulnerability","")).upper() == "YES"),
            sum(1 for r in kv[1] if str(r.get("Public Exploit","")).upper() == "YES"),
            sum(1 for r in kv[1] if str(r.get("CVSS Severity","")).upper() == "CRITICAL"),
            max((_to_float(r.get("Risk Score",0)) for r in kv[1]), default=0.0),
        ),
        reverse=True,
    )

    for (sw_name, sw_ver), sw_rows in sw_ranked:
        sw_rows_sorted = sorted(sw_rows, key=lambda r: _to_float(r.get("Risk Score", 0)), reverse=True)
        crit    = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        high    = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "HIGH")
        kev_c   = sum(1 for r in sw_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        expl_c  = sum(1 for r in sw_rows if str(r.get("Public Exploit","")).upper() == "YES")
        max_rs  = max((_to_float(r.get("Risk Score",0)) for r in sw_rows), default=0.0)
        posture_sw = _risk_posture_label(max_rs, crit, kev_c, expl_c)

        label_parts = posture_sw.split("—")[0].strip()
        lines.append(f"### {sw_name}")
        pub_sw   = str(sw_rows_sorted[0].get("Publisher", "") or "") if sw_rows_sorted else ""
        idate_sw = str(sw_rows_sorted[0].get("Install Date", "") or "") if sw_rows_sorted else ""
        if pub_sw or idate_sw:
            meta_parts = []
            if pub_sw:   meta_parts.append(f"Publisher: {pub_sw}")
            if idate_sw: meta_parts.append(f"Installed: {idate_sw}")
            lines.append(f"*{' | '.join(meta_parts)}*")
        lines.append(f"**Risk Level: {label_parts}**")
        lines.append("")

        # Patch age context for executives
        age_vals: List[int] = []
        for r in sw_rows_sorted:
            try:
                age_vals.append(int(str(r.get("Patch Age (Days)", "") or "")))
            except ValueError:
                pass
        if age_vals:
            max_age_sw = max(age_vals)
            if max_age_sw > 180:
                lines.append(
                    f"⚠ **Long-standing exposure:** Vulnerable software has been installed for over "
                    f"{max_age_sw} days. CVEs disclosed during this period represent an unpatched window "
                    "of risk that has been open for an extended time."
                )
                lines.append("")
            elif max_age_sw > 30:
                lines.append(
                    f"This software has been installed for {max_age_sw} days. "
                    "One or more CVEs were disclosed during the current installation period."
                )
                lines.append("")

        # Business-language description of what the weaknesses allow
        scenarios = _attack_scenario_business(sw_rows_sorted, sw_name)
        if scenarios:
            lines.append("**What this means for the organization:**")
            lines.append("")
            for s in scenarios[:2]:
                lines.append(f"- {s}")
            lines.append("")

        # KEV and exploit statements
        kev_stmt  = _kev_business_statement(kev_c, sw_name)
        expl_stmt = _exploit_business_statement(expl_c, sw_name)
        if kev_stmt:
            lines.append(kev_stmt)
            lines.append("")
        if expl_stmt:
            lines.append(expl_stmt)
            lines.append("")

        # GreyNoise active exploitation signal
        gn_active_sw = sum(
            1 for r in sw_rows
            if _THREAT_INTEL_CACHE.get(r.get("CVE ID",""), {}).get("greynoise", {}).get("noise")
        )
        if gn_active_sw > 0:
            lines.append(
                f"⚠ **Threat monitoring services have detected active exploitation attempts** "
                f"targeting {gn_active_sw} of the weaknesses in {sw_name}. This indicates "
                "adversaries are currently probing or attacking systems with these vulnerabilities."
            )
            lines.append("")

        # Concise severity summary — no CVE IDs, no CVSS numbers
        impact_parts = []
        if crit > 0:
            impact_parts.append(f"{crit} weakness{'es' if crit != 1 else ''} rated as the highest possible severity")
        if high > 0:
            impact_parts.append(f"{high} high-severity weakness{'es' if high != 1 else ''}")
        if impact_parts:
            lines.append(f"**Scope:** {'; '.join(impact_parts)}.")
            lines.append("")

        lines.append("---")
        lines.append("")

    # ── SECTION 4 — ATTACK SCENARIOS ────────────────────────────────────
    lines += [
        "## Attack Scenarios",
        "",
        "The following scenarios describe how an adversary could realistically exploit "
        "the identified weaknesses. These are not hypothetical — they represent documented "
        "attack patterns used by threat actors against organizations with similar exposures.",
        "",
    ]

    # Build scenarios from top ATT&CK techniques across all findings
    scenario_count = 0
    seen_scenario_aids: set = set()
    for aid, cnt, meta in top5:
        if aid in seen_scenario_aids:
            continue
        seen_scenario_aids.add(aid)
        scenario_count += 1
        tactic_list = meta.get("tactics", [])
        narrative   = _technique_to_business(aid, tactic_list)
        tactics_str = ", ".join(tactic_list) if tactic_list else "general attack activity"

        # Determine which software is affected
        affected_sw = []
        for (sn, sv), sw_rows in grouped.items():
            for r in sw_rows:
                attacks = _split_multi(r.get("ATT&CK Techniques",""))
                if any(aid in a for a in attacks):
                    if sn not in affected_sw:
                        affected_sw.append(sn)
                    break

        lines.append(f"### Scenario {scenario_count}: {meta.get('name', aid)}")
        lines.append(f"**Threat phase:** {tactics_str.title()}")
        lines.append(f"**Affects:** {', '.join(affected_sw) if affected_sw else 'Multiple systems'}")
        lines.append("")
        lines.append(narrative)
        lines.append("")

        # Remediation action in business language
        remediation = _TECHNIQUE_REMEDIATION.get(aid)
        if remediation:
            lines.append(f"**How to reduce this risk:** {remediation}")
            lines.append("")

    if scenario_count == 0:
        lines.append("No specific attack scenarios could be mapped from the current findings.")
        lines.append("")

    lines += ["---", ""]

    # ── SECTION 5 — OPERATIONAL & BUSINESS IMPACTS ──────────────────────
    lines += [
        "## Operational and Business Impacts",
        "",
        "If the identified weaknesses are exploited, the organization may experience "
        "the following consequences:",
        "",
    ]

    # Derive impact categories from what was found
    has_rce    = any(aid in seen_scenario_aids for aid in ["T1190","T1059","T1203"])
    has_privesc= "T1068" in seen_scenario_aids or "T1548" in seen_scenario_aids
    has_data   = any(aid in seen_scenario_aids for aid in ["T1005","T1552","T1040","T1557"])
    has_dos    = "T1499" in seen_scenario_aids
    has_persist= any(aid in seen_scenario_aids for aid in ["T1078","T1105"])

    impact_lines: List[str] = []

    if has_rce or kev_total > 0:
        impact_lines.append(
            "**Operational Disruption** — Unauthorized control of systems could disrupt "
            "mission-critical operations, cause unplanned downtime, and require emergency "
            "response resources to contain and recover."
        )
    if has_data:
        impact_lines.append(
            "**Data Breach / Information Loss** — Sensitive organizational data, personnel "
            "records, or intellectual property could be accessed and exfiltrated, triggering "
            "breach notification obligations and reputational damage."
        )
    if has_privesc:
        impact_lines.append(
            "**Escalating Compromise** — Once inside, attackers could gain administrative "
            "control, expanding the scope of a breach well beyond the initial point of entry "
            "and increasing recovery costs significantly."
        )
    if has_dos:
        impact_lines.append(
            "**Service Availability Loss** — Systems could be rendered unavailable, "
            "disrupting operations, impacting customers or mission partners, and incurring "
            "financial loss from downtime."
        )
    if has_persist:
        impact_lines.append(
            "**Long-Term Persistent Access** — Attackers could maintain hidden, long-term "
            "access to organizational systems — surviving remediation efforts — enabling "
            "ongoing data theft, surveillance, or future disruptive action."
        )
    if kev_total > 0:
        impact_lines.append(
            "**Regulatory and Compliance Exposure** — Active exploitation of federal "
            "mandate-listed vulnerabilities may trigger reporting requirements, audit "
            "findings, or contractual penalties depending on your regulatory environment."
        )
    if expl_total > 0 and not kev_total:
        impact_lines.append(
            "**Reputational Risk** — A successful attack exploiting publicly known, "
            "unpatched vulnerabilities may attract external scrutiny and raise questions "
            "about the organization's security posture and due diligence."
        )

    # Supply chain consideration
    sc_sw = [n for n in sw_names if any(
        keyword in n.lower() for keyword in
        ["library","sdk","framework","runtime","driver","agent","client","connector","plugin","module"]
    )]
    if sc_sw:
        impact_lines.append(
            f"**Supply Chain Risk** — Vulnerabilities in foundational software components "
            f"({', '.join(sc_sw[:3])}) could have downstream effects on dependent "
            "applications and services, potentially amplifying the scope of any breach."
        )

    if not impact_lines:
        impact_lines.append(
            "**Operational Risk** — Identified weaknesses, if exploited, could disrupt "
            "operations, expose sensitive data, and require unplanned remediation resources."
        )

    for imp in impact_lines:
        lines.append(f"- {imp}")
        lines.append("")

    lines += ["---", ""]

    # ── SECTION 6 — RISK TRENDS ──────────────────────────────────────────
    lines += [
        "## Risk Trends",
        "",
    ]

    if kev_total > 0 or gn_active_total > 0:
        lines.append(
            "**Exploitation activity is confirmed and current.** The threat environment "
            "for the assessed systems is active:"
        )
        lines.append("")
        if kev_total > 0:
            lines.append(
                f"- **{kev_total} {'vulnerability has' if kev_total == 1 else 'vulnerabilities have'}** "
                "been added to the U.S. government's catalog of weaponized vulnerabilities, "
                "confirming real-world exploitation by threat actors."
            )
        if gn_active_total > 0:
            lines.append(
                f"- **Active scanning and exploitation attempts** have been observed against "
                f"{gn_active_total} of the identified weaknesses, indicating threat actors are "
                "actively targeting systems with these vulnerabilities."
            )
        if expl_total > 0:
            lines.append(
                f"- **{expl_total} {'weakness has' if expl_total == 1 else 'weaknesses have'}** "
                "publicly available attack tools, lowering the barrier for less sophisticated attackers."
            )
    elif expl_total > 0:
        lines.append(
            f"**Attack tools are publicly available** for {expl_total} of the identified "
            "weaknesses. While no confirmed active exploitation has been detected, the "
            "availability of attack tools increases the probability of exploitation over time. "
            "The risk trajectory is upward if remediation is delayed."
        )
    else:
        lines.append(
            "No confirmed active exploitation of the identified weaknesses has been detected "
            "at this time. However, the presence of unpatched vulnerabilities represents an "
            "ongoing and increasing risk as threat actors continue to expand their target sets."
        )
    lines += ["", "---", ""]

    # ── SECTION 7 — STRATEGIC RECOMMENDATIONS ───────────────────────────
    lines += [
        "## Strategic Recommendations",
        "",
        "The following recommendations are directed at leadership and require organizational "
        "decision-making, resourcing, or policy action:",
        "",
    ]

    rec_num = 1
    if kev_total > 0:
        lines.append(
            f"**{rec_num}. Authorize Emergency Remediation** — Direct security and IT teams to "
            f"immediately patch the {kev_total} actively exploited {'weakness' if kev_total == 1 else 'weaknesses'} "
            "identified in this report. Establish a 24–72 hour remediation deadline and "
            "confirm completion."
        )
        lines.append("")
        rec_num += 1

    if sev_counts["CRITICAL"] > 0 or sev_counts["HIGH"] > 0:
        lines.append(
            f"**{rec_num}. Establish a Formal Patch Management Programme** — The volume of "
            f"critical ({sev_counts['CRITICAL']}) and high ({sev_counts['HIGH']}) severity "
            "findings indicates a need for a structured, time-bound patching process with "
            "defined service-level targets and executive visibility into compliance."
        )
        lines.append("")
        rec_num += 1

    lines.append(
        f"**{rec_num}. Verify Monitoring and Detection Coverage** — Confirm that security "
        "monitoring tools are actively watching for signs of exploitation on the systems "
        "identified in this report. Gaps in detection capability increase dwell time if "
        "an attack occurs."
    )
    lines.append("")
    rec_num += 1

    if total_cves > 20:
        lines.append(
            f"**{rec_num}. Invest in Vulnerability Management Capability** — The scale of "
            f"findings ({total_cves} weaknesses across {sw_count} systems) suggests that "
            "vulnerability management may benefit from additional tooling, staffing, or "
            "process improvements to sustain a lower ongoing risk profile."
        )
        lines.append("")
        rec_num += 1

    lines.append(
        f"**{rec_num}. Schedule a Follow-On Assessment** — After completing remediation, "
        "conduct a validation scan to confirm the risk has been reduced and to identify "
        "any newly disclosed vulnerabilities in the assessed systems."
    )
    lines.append("")
    lines += ["---", ""]

    # ── SECTION 8 — RESOURCE IMPLICATIONS ───────────────────────────────
    lines += [
        "## Resource Implications",
        "",
        "Addressing the findings in this report will require coordination across IT, "
        "security, and operational teams. The following resource categories should be "
        "considered:",
        "",
    ]

    if kev_total > 0:
        lines.append(
            "- **Immediate response capacity** — Security and IT personnel will need to be "
            f"allocated for emergency patching of the {kev_total} actively exploited "
            "{'system' if kev_total == 1 else 'systems'}, potentially requiring after-hours effort."
        )
    if sev_counts["CRITICAL"] + sev_counts["HIGH"] > 0:
        lines.append(
            f"- **Planned remediation effort** — Patching and hardening {sev_counts['CRITICAL'] + sev_counts['HIGH']} "
            "critical and high-severity findings across the assessed systems will require "
            "scheduled maintenance windows, testing, and change-management processes."
        )
    lines += [
        "- **Testing and validation** — Patches must be tested in non-production environments "
        "before deployment to avoid operational disruption, and re-scanned post-deployment "
        "to confirm effectiveness.",
        "- **Monitoring uplift** — If detection gaps exist, investment in security monitoring "
        "tools or managed security services may be warranted to improve response capability.",
        "",
        "---",
        "",
    ]

    # ── SECTION 9 — PRIORITIZED REMEDIATION ROADMAP ─────────────────────
    lines += [
        "## Prioritized Remediation Roadmap",
        "",
        "The following tiered action plan is recommended, ordered by urgency and impact:",
        "",
        "| Priority | Timeframe | Action | Rationale |",
        "|---|---|---|---|",
    ]

    if kev_total > 0:
        lines.append(
            f"| **1 — Emergency** | 24–72 hours | Apply patches for {kev_total} actively exploited "
            f"{'weakness' if kev_total == 1 else 'weaknesses'} | Confirmed real-world exploitation — "
            "highest probability of immediate harm |"
        )
    if sev_counts["CRITICAL"] > 0:
        lines.append(
            f"| **2 — Critical** | Within 7 days | Remediate {sev_counts['CRITICAL']} critical-severity "
            "weaknesses | Exploitation would have maximum organizational impact |"
        )
    if expl_total > 0:
        lines.append(
            f"| **3 — Urgent** | Within 14 days | Address {expl_total} weaknesses with public attack tools | "
            "Attack barrier is low; exploitation probability is elevated |"
        )
    if sev_counts["HIGH"] > 0:
        lines.append(
            f"| **4 — High Priority** | Within 30 days | Patch {sev_counts['HIGH']} high-severity weaknesses | "
            "Significant potential impact; systematic remediation required |"
        )
    if sev_counts["MEDIUM"] + sev_counts["LOW"] > 0:
        lines.append(
            f"| **5 — Routine** | Within 90 days | Address remaining {sev_counts['MEDIUM'] + sev_counts['LOW']} "
            "moderate and low-severity findings | Standard patch cadence is appropriate |"
        )
    lines.append(
        "| **Ongoing** | Continuous | Re-scan after each remediation wave; subscribe to vendor advisories | "
        "New vulnerabilities are disclosed continuously; sustained vigilance is required |"
    )
    lines += ["", "---", ""]

    # ── SECTION 10 — RESIDUAL ORGANIZATIONAL RISK ───────────────────────
    lines += [
        "## Residual Organizational Risk",
        "",
        "Even after completing the remediation roadmap above, a degree of residual "
        "risk will remain. Leadership should be aware of the following:",
        "",
    ]

    residual: List[str] = []
    residual.append(
        "**New vulnerabilities will continue to be disclosed** in the assessed software. "
        "The remediation of today's findings does not guarantee the absence of future risk — "
        "a continuous monitoring and patching programme is essential."
    )
    if sev_counts["MEDIUM"] + sev_counts["LOW"] > 0:
        residual.append(
            f"**{sev_counts['MEDIUM'] + sev_counts['LOW']} moderate and lower-severity weaknesses** "
            "will remain until the routine remediation phase is complete. While individually "
            "less impactful, attackers can chain lower-severity weaknesses to achieve "
            "significant outcomes."
        )
    if total_cves > confirmed_total and confirmed_total > 0:
        residual.append(
            "**Not all identified weaknesses have been version-confirmed** against the exact "
            "software deployed. Some findings are based on product matching and may not all "
            "apply — a targeted review by IT teams is recommended to validate applicability."
        )
    residual.append(
        "**Human factors and process gaps** — technical patching addresses software "
        "vulnerabilities but does not mitigate risks arising from phishing, weak passwords, "
        "insider threats, or misconfigured access controls. A holistic security programme "
        "should address these dimensions in parallel."
    )
    residual.append(
        "**Supply chain and third-party risk** — this assessment covers identified software "
        "components but does not account for vulnerabilities in third-party services, "
        "cloud providers, or vendor-managed systems that may pose indirect risk."
    )

    for r_item in residual:
        lines.append(f"- {r_item}")
        lines.append("")

    full_md  = "\n".join(lines).strip() + "\n"
    logo_b64 = _load_logo_b64()

    return _wrap_html_report(
        title=report_title,
        body_md=full_md,
        logo_b64=logo_b64,
        subtitle="Cyber Risk Brief — Executive & Leadership Audience",
        toc_html=toc_html,
    )


# ======================================================================
#  TECHNICAL REPORT — Module-level data structures and helpers
# ======================================================================

_CWE_TECHNICAL_IMPACT: Dict[str, str] = {
    "CWE-78":   "OS command injection — attacker-supplied input is executed by the operating system shell, enabling arbitrary command execution with the privileges of the affected process.",
    "CWE-77":   "Command injection — unsanitized input is interpreted as shell commands, enabling arbitrary command execution.",
    "CWE-89":   "SQL injection — attacker-controlled input is interpreted as SQL, enabling unauthorized database read/write, authentication bypass, or lateral movement via linked servers.",
    "CWE-79":   "Cross-site scripting (XSS) — attacker-controlled script executes in victim browsers, enabling session hijacking, credential theft, or DOM manipulation.",
    "CWE-94":   "Code injection — attacker-supplied data is evaluated as executable code, bypassing application logic and enabling arbitrary execution.",
    "CWE-502":  "Deserialization of untrusted data — crafted serialized objects trigger arbitrary code execution or object injection during the deserialization process.",
    "CWE-119":  "Buffer overflow — memory corruption outside allocated bounds can corrupt adjacent heap/stack structures, enabling controlled code execution or denial of service.",
    "CWE-120":  "Classic buffer overflow — unbounded copy operations write past allocation boundaries, creating direct memory corruption primitives for exploitation.",
    "CWE-125":  "Out-of-bounds read — memory read beyond buffer boundaries leaks adjacent heap/stack content, potentially disclosing pointers, keys, or sensitive data.",
    "CWE-787":  "Out-of-bounds write — memory corruption primitive enabling heap/stack manipulation for controlled code execution or privilege escalation.",
    "CWE-416":  "Use-after-free — access to freed memory regions creates type confusion and read/write primitives exploitable for code execution.",
    "CWE-476":  "NULL pointer dereference — process crash on NULL dereference, exploitable as a denial-of-service primitive; rarely exploitable for code execution.",
    "CWE-190":  "Integer overflow — arithmetic overflow corrupts size or index calculations, creating heap overflow conditions downstream.",
    "CWE-122":  "Heap-based buffer overflow — off-by-N writes on the heap corrupt allocator metadata or adjacent objects, enabling code execution.",
    "CWE-22":   "Path traversal — unsanitized path separators (../) allow reads/writes outside the intended directory, enabling config disclosure, log poisoning, or code placement.",
    "CWE-434":  "Unrestricted file upload — server accepts attacker-supplied files without type validation, enabling web shell deployment or malicious library loading.",
    "CWE-287":  "Authentication bypass — authentication logic can be circumvented without valid credentials, granting unauthorized access.",
    "CWE-306":  "Missing authentication — critical functionality exposed without authentication requirement.",
    "CWE-862":  "Missing authorization — authenticated users can access resources or operations beyond their intended privilege level.",
    "CWE-863":  "Incorrect authorization — access control checks are performed against incorrect principals or contexts.",
    "CWE-269":  "Improper privilege management — privileges are acquired, retained, or released incorrectly, enabling privilege escalation or lock-in of elevated rights.",
    "CWE-798":  "Hard-coded credentials — static credentials embedded in code or binaries are extractable via reverse engineering, providing unconditional authentication bypass.",
    "CWE-521":  "Weak password requirements — no enforcement of complexity or length minimums, enabling brute-force and dictionary attacks.",
    "CWE-307":  "Improper restriction of authentication attempts — no lockout or rate-limiting, enabling unlimited credential guessing.",
    "CWE-327":  "Use of broken cryptographic algorithm — deprecated cipher suite (e.g., RC4, DES, MD5) susceptible to known cryptanalytic attacks.",
    "CWE-295":  "Improper certificate validation — TLS certificate chain not validated, enabling MitM attacks on encrypted channels.",
    "CWE-326":  "Inadequate encryption strength — key length below modern standards vulnerable to factoring or discrete-log attacks.",
    "CWE-319":  "Cleartext transmission — sensitive data transmitted without encryption, interceptable by passive network adversaries.",
    "CWE-200":  "Information exposure — internal state, stack traces, or sensitive data returned to unauthorized parties.",
    "CWE-532":  "Information exposure through log files — credentials, tokens, or PII written to logs accessible beyond intended audience.",
    "CWE-611":  "XML external entity (XXE) injection — XML parser processes external entity declarations, enabling SSRF, file disclosure, or denial of service.",
    "CWE-400":  "Uncontrolled resource consumption — absent resource limits allow attacker-driven memory exhaustion, CPU saturation, or thread starvation.",
    "CWE-770":  "Allocation of resources without limits — unbounded allocation leads to OOM conditions or connection exhaustion under adversarial load.",
    "CWE-918":  "Server-side request forgery (SSRF) — server fetches attacker-specified URIs, enabling access to internal services, metadata endpoints, or cloud IMDS.",
    "CWE-352":  "Cross-site request forgery (CSRF) — absent CSRF token allows attacker-crafted pages to trigger authenticated actions in victim sessions.",
    "CWE-732":  "Incorrect permission assignment — files or directories with overly permissive ACLs allow unauthorized read, write, or execution.",
    "CWE-276":  "Incorrect default permissions — installation creates resources with world-readable or world-writable permissions.",
    "CWE-362":  "Race condition (TOCTOU) — time-of-check to time-of-use window enables privilege escalation via symlink or file substitution attacks.",
    "CWE-20":   "Improper input validation — insufficient bounds or type checking on external input; root cause for many injection, overflow, and traversal vulnerabilities.",
}

_ARCH_RISK_CWES: Dict[str, str] = {
    "CWE-798": "Hard-coded credentials detected — this is an architectural defect requiring design remediation, not a configuration patch.",
    "CWE-319": "Cleartext protocol exposure — persistent architectural risk until the protocol is upgraded to an encrypted equivalent.",
    "CWE-295": "Certificate validation bypass — renders encrypted channels equivalent to plaintext for attacker purposes.",
    "CWE-306": "Missing authentication — fundamental access control design gap not addressable by patching alone.",
    "CWE-502": "Deserialization attack surface — consider migration to safer serialization formats (JSON, Protocol Buffers).",
    "CWE-918": "SSRF attack surface — server-side request capabilities without allowlist enforcement expose cloud metadata endpoints and internal services.",
    "CWE-611": "XXE attack surface — XML parsers with external entity processing enabled present a persistent SSRF and file-disclosure risk.",
}

_TECHNIQUE_DETECTION: Dict[str, List[str]] = {
    "T1190": [
        "Monitor web/application server logs for anomalous request patterns: unusually long query strings, encoded payloads, or unexpected HTTP verbs.",
        "Alert on process creation where the parent is a web server process (e.g., IIS spawning cmd.exe, Apache spawning /bin/sh).",
        "Deploy WAF rules to detect and block common exploitation patterns (SQLi, XSS, command injection payloads).",
        "Monitor for unexpected outbound connections from application server hosts following inbound exploit attempts.",
    ],
    "T1068": [
        "Enable process creation auditing (Windows Event 4688 / Linux auditd execve) and alert on privilege transitions to SYSTEM/root.",
        "Monitor for token impersonation API calls (NtCreateToken, ZwDuplicateToken) from non-privileged processes.",
        "Alert on unexpected writes to privileged directories from unprivileged processes.",
    ],
    "T1059": [
        "Log and alert on suspicious command-line arguments: base64 blobs, -EncodedCommand, IEX, Invoke-Expression, curl|bash patterns.",
        "Enable Script Block Logging (PowerShell) and Module Logging; forward to SIEM.",
        "Alert on unusual parent-child process chains (e.g., web server spawning interpreter).",
    ],
    "T1203": [
        "Deploy EDR with memory-scanning and shellcode detection on all endpoints.",
        "Enforce Exploit Protection settings (DEP, ASLR, CFG, SEHOP) on the affected application.",
    ],
    "T1078": [
        "Alert on authentication from unusual source IPs or at anomalous times relative to historical baseline.",
        "Monitor for credential stuffing indicators: high failure-to-success ratio from single IPs.",
        "Enable MFA; alert on MFA bypass attempts.",
    ],
    "T1499": [
        "Establish rate-limiting and connection throttling at the network edge.",
        "Monitor for volumetric anomalies: sudden bandwidth spikes, connection-rate outliers.",
        "Enable SYN cookies on affected hosts.",
    ],
    "T1005": [
        "Enable file access auditing on sensitive directories; alert on bulk read operations.",
        "Monitor for staging indicators: large archive creation in temp directories.",
    ],
    "T1110": [
        "Alert on repeated authentication failures from single sources exceeding threshold.",
        "Enable account lockout policies; monitor lockout events as indicators of brute-force campaigns.",
    ],
    "T1548": [
        "Audit UAC bypass events (Windows Event 4673, 4674).",
        "Monitor sudo command execution on Linux; alert on unusual privilege grants.",
    ],
    "T1552": [
        "Alert on access to known credential storage locations: Windows Credential Manager, SAM hive, .ssh/ directories.",
        "Deploy secrets scanning in CI/CD pipelines.",
    ],
}

_TECHNIQUE_MITIGATION: Dict[str, List[str]] = {
    "T1190": [
        "Apply the vendor security patch immediately. Verify the patched version is deployed.",
        "Implement strict input validation and parameterized queries at the application layer.",
        "Restrict network access to the affected service using host-based firewall rules or network ACLs.",
        "Deploy a WAF as a compensating control pending patch deployment.",
    ],
    "T1068": [
        "Apply the vendor patch. Patch both the PE vector and any initial access CVEs.",
        "Enforce mandatory integrity controls; apply SELinux/AppArmor profiles.",
        "Enable kernel exploit mitigations: Credential Guard, SMEP/SMAP.",
        "Audit and reduce service account privileges; apply principle of least privilege.",
    ],
    "T1059": [
        "Disable or restrict the relevant interpreter where not operationally required.",
        "Apply application whitelisting (AppLocker/WDAC) to prevent unauthorized script execution.",
        "Restrict the affected application's ability to spawn child processes.",
    ],
    "T1203": [
        "Apply the vendor patch.",
        "Enable Exploit Protection controls: DEP, ASLR, CFG, and SEHOP.",
        "Deploy EDR with memory-resident exploit detection on all endpoints.",
    ],
    "T1078": [
        "Enforce MFA on all external-facing and privileged authentication endpoints.",
        "Rotate all credentials that may be exposed; audit recently authenticated sessions.",
        "Implement account lockout and alerting for failed authentication patterns.",
    ],
    "T1499": [
        "Apply the patch to eliminate the resource exhaustion primitive.",
        "Implement rate limiting at the load balancer or reverse proxy.",
        "Enable OS-level resource limits (ulimit, cgroups) to prevent single-process exhaustion.",
    ],
    "T1005": [
        "Apply the patch. Enforce filesystem ACLs restricting the affected process.",
        "Implement file integrity monitoring on sensitive directories.",
        "Encrypt sensitive data at rest.",
    ],
    "T1110": [
        "Enforce account lockout with exponential back-off.",
        "Deploy MFA — credential knowledge alone becomes insufficient.",
        "Enforce a strong password policy (minimum 12 characters, breach-password screening).",
    ],
    "T1548": [
        "Apply the patch that eliminates the privilege escalation path.",
        "Enforce least privilege: revoke local admin rights from standard user accounts.",
        "Enable and tune UAC (Windows) or sudo access controls (Linux).",
    ],
    "T1552": [
        "Remove hard-coded credentials from code; migrate secrets to a vault solution.",
        "Rotate all secrets that may have been exposed; revoke compromised API keys immediately.",
        "Implement automated secrets scanning in the CI/CD pipeline.",
    ],
}

_NIST_IMPL: Dict[str, str] = {
    "SI-2":  "Flaw Remediation — establish a patching SLA; track open vulnerabilities in a POA&M; verify remediation by re-scanning.",
    "RA-5":  "Vulnerability Scanning — run authenticated scans on a defined cadence; feed results into risk management workflow.",
    "CM-6":  "Configuration Settings — enforce CIS/DISA STIG baselines; use configuration management tooling to detect drift.",
    "CM-7":  "Least Functionality — disable unused services, ports, and protocols; maintain an approved software list.",
    "AC-3":  "Access Enforcement — enforce role-based access control; review entitlements quarterly.",
    "AC-6":  "Least Privilege — restrict user and service account rights to the minimum required for function.",
    "AC-17": "Remote Access — enforce MFA and encrypted channels for all remote access; log and monitor sessions.",
    "IA-2":  "Identification and Authentication — enforce MFA for all privileged and remote access.",
    "IA-5":  "Authenticator Management — enforce password complexity, rotation, and breach-credential screening.",
    "SC-5":  "Denial of Service Protection — implement rate-limiting, resource quotas, and upstream scrubbing.",
    "SC-7":  "Boundary Protection — enforce network segmentation; restrict inter-zone traffic to documented flows.",
    "SC-8":  "Transmission Confidentiality and Integrity — enforce TLS 1.2+ on all data-in-transit paths.",
    "SC-28": "Protection of Information at Rest — enforce encryption at rest for sensitive data stores.",
    "AU-2":  "Event Logging — enable and forward security-relevant logs to a SIEM; define retention policy.",
    "AU-6":  "Audit Review and Analysis — review logs on a defined cadence; establish alerting on key indicators.",
    "SA-11": "Developer Security Testing — require SAST/DAST in the SDLC; track findings through to closure.",
    "IR-4":  "Incident Handling — maintain and test an incident response plan covering vulnerability exploitation scenarios.",
    "SR-3":  "Supply Chain Controls — assess third-party component risk; maintain a software bill of materials.",
}


def _cve_chain_analysis(sw_rows: List[Dict[str, Any]]) -> List[str]:
    """Identify vulnerability chaining opportunities within a software item."""
    chains: List[str] = []
    cve_by_technique: Dict[str, List[str]] = defaultdict(list)
    has_initial_access = has_privesc = has_execution = has_cred_access = has_lateral = False
    initial_access_cves: List[str] = []
    privesc_cves:        List[str] = []
    execution_cves:      List[str] = []

    for r in sw_rows:
        cid     = r.get("CVE ID", "")
        attacks = _split_multi(r.get("ATT&CK Techniques", ""))
        tactics = [t.lower().replace(" ", "-") for t in _split_multi(r.get("ATT&CK Tactics", ""))]
        for atk in attacks:
            m = re.match(r"^([A-Z0-9.]+)", atk)
            if m:
                cve_by_technique[m.group(1)].append(cid)
        if "initial-access" in tactics:
            has_initial_access = True; initial_access_cves.append(cid)
        if "privilege-escalation" in tactics:
            has_privesc = True; privesc_cves.append(cid)
        if "execution" in tactics:
            has_execution = True; execution_cves.append(cid)
        if "credential-access" in tactics:
            has_cred_access = True
        if "lateral-movement" in tactics:
            has_lateral = True

    if has_initial_access and has_privesc:
        ia_ex = ", ".join(initial_access_cves[:2]) or "initial-access CVE"
        pe_ex = ", ".join(privesc_cves[:2]) or "privilege-escalation CVE"
        chains.append(
            f"**Initial Access → Privilege Escalation:** {ia_ex} enables remote code execution "
            f"as a low-privileged process. {pe_ex} can subsequently be exploited to elevate to "
            "SYSTEM/root. High-confidence two-stage attack path requiring remediation of both CVEs."
        )
    if has_initial_access and has_execution and has_cred_access:
        chains.append(
            f"**Initial Access → Execution → Credential Harvesting:** An attacker gaining execution "
            f"via {initial_access_cves[0] if initial_access_cves else 'an initial-access CVE'} could "
            "deploy credential-harvesting tooling, acquiring credentials for lateral movement."
        )
    if has_execution and has_lateral:
        chains.append(
            "**Execution → Lateral Movement:** Exploitation of execution-enabling CVEs combined with "
            "lateral movement attack paths creates a viable pivot scenario."
        )
    high_freq = [(tid, cves) for tid, cves in cve_by_technique.items() if len(cves) >= 3]
    if high_freq:
        tid, cves = high_freq[0]
        chains.append(
            f"**Technique Amplification — {tid}:** {len(cves)} independent CVEs map to this technique. "
            "Patching one does not close the full attack surface."
        )
    return chains


def _format_cve_engineering(r: Dict[str, Any], sw_name: str) -> List[str]:
    """Format a single CVE into a detailed engineering assessment entry."""
    cid      = r.get("CVE ID", "")
    nvd_url  = r.get("NVD URL", "") or f"https://nvd.nist.gov/vuln/detail/{cid}"
    desc     = str(r.get("Description", "") or "").strip() or "No description available."
    score    = r.get("CVSS Base Score", "N/A")
    sev      = str(r.get("CVSS Severity", "") or "").upper()
    vector   = str(r.get("CVSS Vector", "") or "")
    rs       = r.get("Risk Score", "")
    rl       = r.get("Risk Level", "")
    kev_f    = str(r.get("Known Exploited Vulnerability", "")).upper() == "YES"
    expl_f   = str(r.get("Public Exploit", "")).upper() == "YES"
    epss     = r.get("EPSS Score", "")
    conf     = str(r.get("Version Confirmed", "") or "")
    cwes     = _split_multi(r.get("CWE", ""))
    attacks  = _split_multi(r.get("ATT&CK Techniques", ""))
    tactics  = _split_multi(r.get("ATT&CK Tactics", ""))
    d3fend   = _split_multi(r.get("D3FEND Countermeasures", ""))
    nist     = _split_multi(r.get("NIST 800-53 Controls", ""))
    expl_src = str(r.get("Exploit Sources", "") or "")
    pub_date = str(r.get("CVE Date", "") or "")
    gn       = _THREAT_INTEL_CACHE.get(cid, {}).get("greynoise", {})
    gn_active = gn.get("noise", False)
    gn_riot   = gn.get("riot", False)
    circl     = _THREAT_INTEL_CACHE.get(cid, {}).get("circl", {})
    capecs    = circl.get("capec") or []

    block: List[str] = []
    block.append(f"## {cid}")

    badges = []
    if sev:       badges.append(f"[{sev}]")
    if kev_f:     badges.append("⚠ KEV")
    if expl_f:    badges.append("🔴 PUBLIC EXPLOIT")
    if gn_active: badges.append("🟠 ACTIVE IN-WILD")
    block.append(f"**{'  '.join(badges)}**" if badges else "")
    block.append("")

    block.append("| Field | Value |")
    block.append("|---|---|")
    block.append(f"| CVE ID | [{cid}]({nvd_url}) |")
    block.append(f"| CVSS Base Score | {score} ({sev}) |")
    if vector:
        block.append(f"| CVSS Vector | `{vector}` |")
    block.append(f"| Draugr Risk Score | {rs} / 100 ({rl}) |")
    block.append(f"| EPSS (30-day exploitation probability) | {epss} |")
    block.append(f"| CISA KEV Listed | {'Yes — active exploitation confirmed' if kev_f else 'No'} |")
    if expl_f:
        src_lines = "<br>".join(expl_src.split("; ")) if expl_src else "see NVD"
        block.append(f"| Public Exploit Available | Yes —<br>{src_lines} |")
    else:
        block.append("| Public Exploit Available | No |")
    block.append(f"| Version Confirmed | {conf if conf else 'Unverified — based on CPE product match'} |")
    block.append(f"| Published | {pub_date} |")
    sw_pub   = str(r.get("Publisher", "") or "")
    sw_idate = str(r.get("Install Date", "") or "")
    patch_age = str(r.get("Patch Age (Days)", "") or "")
    if sw_pub:    block.append(f"| Publisher | {sw_pub} |")
    if sw_idate:  block.append(f"| Install Date | {sw_idate} |")
    if patch_age:
        if patch_age == "0 (installed after CVE published)":
            block.append("| Patch Age | Not vulnerable at install — CVE published before install date |")
        else:
            try:
                age_int = int(patch_age)
                age_note = " ⚠ OVERDUE" if (age_int > 30 and kev_f) or age_int > 90 else ""
                block.append(f"| Patch Age | {patch_age} days since install{age_note} |")
            except ValueError:
                block.append(f"| Patch Age | {patch_age} |")
    if gn_active: block.append("| GreyNoise | Active exploitation traffic observed |")
    elif gn_riot: block.append("| GreyNoise | Known scanner/research activity observed |")
    block.append("")

    block.append("### Affected Component and Technical Description")
    block.append(f"**Affected Software:** {sw_name}")
    block.append(f"**Technical Description:** {desc}")
    block.append("")

    if cwes:
        block.append("### Weakness Classification (CWE)")
        for cwe in cwes:
            cwe_num = cwe.replace("CWE-", "")
            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            impact  = _CWE_TECHNICAL_IMPACT.get(cwe, "See CWE reference.")
            block.append(f"- **[{cwe}]({cwe_url}):** {impact}")
        for cwe in cwes:
            arch = _ARCH_RISK_CWES.get(cwe)
            if arch:
                block.append(f"- **Architectural Risk ({cwe}):** {arch}")
        block.append("")

    block.append("### Exploitability Analysis")
    expl_conditions: List[str] = []
    if vector:
        v = vector.upper()
        if   "AV:N" in v: expl_conditions.append("**Attack Vector: Network** — exploitable remotely without physical or adjacent network access")
        elif "AV:A" in v: expl_conditions.append("**Attack Vector: Adjacent** — requires attacker to be on the same network segment")
        elif "AV:L" in v: expl_conditions.append("**Attack Vector: Local** — requires local code execution as a prerequisite")
        elif "AV:P" in v: expl_conditions.append("**Attack Vector: Physical** — requires physical access")
        if   "PR:N" in v: expl_conditions.append("**Privileges Required: None** — no prior authentication required")
        elif "PR:L" in v: expl_conditions.append("**Privileges Required: Low** — requires low-privilege authenticated access")
        elif "PR:H" in v: expl_conditions.append("**Privileges Required: High** — requires administrative access as a prerequisite")
        if   "UI:N" in v: expl_conditions.append("**User Interaction: None** — enables autonomous/worm-like propagation")
        elif "UI:R" in v: expl_conditions.append("**User Interaction: Required** — victim must perform an action")
        if   "AC:L" in v: expl_conditions.append("**Attack Complexity: Low** — exploitation is straightforward and repeatable")
        elif "AC:H" in v: expl_conditions.append("**Attack Complexity: High** — exploitation requires specific conditions")
        if   "S:C"  in v: expl_conditions.append("**Scope: Changed** — can affect components beyond the vulnerable boundary")
    if expl_f:
        src_lines = "\n  - ".join(expl_src.split("; ")) if expl_src else "check NVD and Vulners"
        expl_conditions.append(f"**Public Exploit Code Exists** — exploitation barrier is low.\n  - {src_lines}")
    if kev_f:    expl_conditions.append("**CISA KEV Confirmed** — actively exploited by threat actors in real-world campaigns.")
    if gn_active:expl_conditions.append("**GreyNoise Active Signal** — exploitation or scanning attempts observed in the wild.")
    try:
        epss_val = float(str(epss).rstrip("%"))
        if epss_val >= 10.0:
            expl_conditions.append(f"**High EPSS ({epss})** — top-decile exploitation probability.")
        elif epss_val >= 1.0:
            expl_conditions.append(f"**Moderate EPSS ({epss})** — meaningful exploitation probability within 30 days.")
    except (ValueError, TypeError):
        pass
    for ec in expl_conditions:
        block.append(f"- {ec}")
    if not expl_conditions:
        block.append("- Consult the NVD advisory for CVSS vector detail.")
    block.append("")

    if attacks:
        block.append("### MITRE ATT&CK Mapping")
        for atk in attacks:
            m = re.match(r"^([A-Z0-9.]+)\s*\((.*?)\)$", atk)
            if m:
                tid, tname = m.group(1), m.group(2)
                atk_url = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
                block.append(f"- **[{tid} — {tname}]({atk_url})**")
            else:
                block.append(f"- {atk}")
        if tactics:
            block.append(f"- **Tactics:** {', '.join(tactics)}")
        if capecs:
            capec_str = "; ".join(f"CAPEC-{c.get('id','')} {c.get('name','')}" for c in capecs[:3])
            block.append(f"- **CAPEC Attack Patterns:** {capec_str}")
        block.append("")

    if attacks:
        first = attacks[0]
        m2 = re.match(r"^([A-Z0-9.]+)\s*\((.*?)\)$", first)
        if m2:
            aid, aname = m2.group(1), m2.group(2)
        else:
            aid, aname = first, first
        scenario_info = SCENARIOS.get(aid)
        if scenario_info and scenario_info.get("description"):
            narrative = scenario_info["description"].format(cve_id=cid, software_name=sw_name)
        else:
            narrative = _scenario_template(aid, aname, sw_name, cid)
        impact_text = get_impact(aid)
        block.append("### Threat Scenario")
        block.append(narrative)
        if impact_text:
            block.append(f"**Expected Impact:** {impact_text}")
        block.append("")

    block.append("### Operational Impact")
    op_impacts: List[str] = []
    if sev == "CRITICAL":
        op_impacts.append("Potential for complete compromise; recovery may require system rebuild.")
    if kev_f or gn_active:
        op_impacts.append("Active exploitation confirmed or observed — elevate incident response posture.")
    if expl_f:
        op_impacts.append("Public exploit availability reduces the technical barrier for low-skilled threat actors.")
    if conf.upper() == "YES":
        op_impacts.append("Version-confirmed — confirmed exposure, not a speculative CPE match.")
    elif not conf:
        op_impacts.append("Version confirmation pending — manual validation against deployed build recommended.")
    for oip in op_impacts:
        block.append(f"- {oip}")
    if not op_impacts:
        block.append("- Assess operational impact based on the function and network exposure of the affected component.")
    block.append("")

    block.append("### Detection Recommendations")
    first_aid = ""
    if attacks:
        m3 = re.match(r"^([A-Z0-9.]+)", attacks[0])
        if m3: first_aid = m3.group(1)
    det_recs = _TECHNIQUE_DETECTION.get(first_aid, [])
    cwe_det: List[str] = []
    for cwe in cwes:
        if cwe == "CWE-89":  cwe_det.append("Monitor application logs for anomalous SQL syntax; enable WAF SQL injection rule sets.")
        elif cwe == "CWE-79": cwe_det.append("Monitor for script injection payloads in web request parameters; enforce CSP headers.")
        elif cwe == "CWE-798":cwe_det.append("Alert on authentication using credentials extracted from code repositories or binary analysis.")
        elif cwe == "CWE-502":cwe_det.append("Alert on deserialization operations from externally-sourced data.")
    for d in (det_recs + cwe_det)[:5]:
        block.append(f"- {d}")
    if not det_recs and not cwe_det:
        block.append("- Review the NVD advisory and vendor security bulletin for CVE-specific exploitation indicators.")
        block.append("- Enable verbose logging on the affected service and forward to SIEM.")
    block.append("")

    block.append("### Mitigation Recommendations")
    first_aid2 = ""
    if attacks:
        m4 = re.match(r"^([A-Z0-9.]+)", attacks[0])
        if m4: first_aid2 = m4.group(1)
    mit_recs = _TECHNIQUE_MITIGATION.get(first_aid2, [])
    block.append(f"1. **Apply vendor patch** — consult the [NVD advisory]({nvd_url}) for patch details.")
    step = 2
    for mr in mit_recs[:4]:
        block.append(f"{step}. {mr}")
        step += 1
    if d3fend:
        for cm in d3fend[:3]:
            d3f_slug = cm.replace(" ", "")
            d3f_url  = f"https://d3fend.mitre.org/technique/d3f:{d3f_slug}/"
            block.append(f"{step}. Deploy [D3FEND countermeasure: {cm}]({d3f_url})")
            step += 1
    block.append("")

    if nist:
        block.append("### Applicable NIST SP 800-53 Controls")
        block.append("| Control ID | Control Name | Implementation Guidance |")
        block.append("|---|---|---|")
        for ctrl in nist[:6]:
            ctrl_id  = ctrl.split()[0] if ctrl.split() else ctrl
            ctrl_url = f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={ctrl_id}"
            note     = _NIST_IMPL.get(ctrl_id, "Refer to NIST SP 800-53 Rev 5.")
            block.append(f"| [{ctrl_id}]({ctrl_url}) | {ctrl} | {note} |")
        block.append("")

    block.append("---")
    block.append("")
    return block


_D3FEND_GENERIC: List[str] = [
    "Review the D3FEND technique page for specific implementation guidance.",
    "Apply network segmentation to limit the attack surface for this technique.",
    "Enable detection logging relevant to this technique class and forward to SIEM.",
    "Enforce least-privilege access controls on systems exposed to this technique.",
    "Validate compensating control effectiveness through purple-team or tabletop exercise.",
]

_D3FEND_IMPL: Dict[str, List[str]] = {
    "Network Traffic Filtering": [
        "Define and enforce allowlist-based firewall rules for all inbound and outbound traffic on affected hosts.",
        "Block or restrict access to the affected service port from untrusted network segments.",
        "Deploy IDS/IPS signatures for CVEs identified in this scan.",
        "Implement egress filtering to prevent outbound C2 connections from affected hosts.",
        "Enable logging on all perimeter and internal firewall rules touching the affected service.",
    ],
    "Software Update": [
        "Apply the vendor security patch immediately; verify the deployed version string post-patch.",
        "Subscribe to vendor security advisories for automated notification of future patches.",
        "Integrate patch status into your vulnerability management platform and track open findings.",
        "Establish a patch SLA: Critical <=72h, High <=7d, Medium <=30d, Low <=90d.",
        "Verify remediation by re-scanning the asset after patching.",
    ],
    "Credential Hardening": [
        "Rotate all service-account and administrative credentials for affected software.",
        "Enforce multi-factor authentication on all privileged accounts accessing the affected service.",
        "Audit and remove stale, default, or shared credentials from the affected system.",
        "Implement a privileged access workstation (PAW) policy for administrative access.",
        "Store secrets in a vault solution rather than config files or code.",
    ],
    "Execution Isolation": [
        "Run the affected service in a dedicated container or VM to limit blast radius.",
        "Apply AppArmor or SELinux mandatory-access-control profiles to the service process.",
        "Restrict interpreter access (PowerShell, bash, Python) to authorised users only.",
        "Implement application whitelisting so only signed binaries may execute.",
        "Review and tighten OS-level user rights assignments for the service account.",
    ],
    "File Analysis": [
        "Deploy EDR with memory-scanning and behavioural analysis on the affected host.",
        "Enable file integrity monitoring (FIM) on service binaries and configuration directories.",
        "Scan uploaded or received files for malicious content before processing.",
        "Alert on unexpected writes to critical system directories.",
    ],
    "Process Spawn Analysis": [
        "Enable process creation auditing (Windows Event 4688 / Linux auditd execve).",
        "Alert on unusual parent-child process chains (e.g., web server spawning cmd.exe).",
        "Restrict which processes may spawn child processes using AppArmor, SELinux, or Job Objects.",
        "Monitor for interpreter invocations from unexpected parent processes.",
    ],
    "System Call Analysis": [
        "Deploy seccomp profiles to restrict system calls available to the affected process.",
        "Enable kernel auditing for sensitive syscalls (execve, ptrace, open) on affected hosts.",
        "Alert on privilege-escalation syscall patterns from unprivileged processes.",
    ],
    "User Behaviour Analysis": [
        "Establish a behavioural baseline for accounts that access the affected system.",
        "Alert on authentication anomalies: off-hours access, unusual source IPs, unexpected user agents.",
        "Monitor for bulk data access or exfiltration indicators following authentication.",
        "Implement UEBA tooling to detect lateral movement following initial compromise.",
    ],
    "Certificate Analysis": [
        "Enforce TLS 1.2+ with valid, trusted certificate chains on all affected communication paths.",
        "Implement certificate pinning for high-value service-to-service communications.",
        "Monitor Certificate Transparency logs for unexpected certificates for your domains.",
        "Enable HSTS headers on all externally-facing HTTPS services.",
    ],
    "Application Configuration Hardening": [
        "Apply vendor-recommended hardening guide or CIS benchmark for the affected software.",
        "Disable all unused features, modules, APIs, and services within the application.",
        "Enforce secure-by-default configuration: disable debug modes, restrict error detail.",
        "Review and restrict application file-system and network permissions to the minimum required.",
        "Validate configuration with automated compliance tooling on a defined cadence.",
    ],
}


def _defensive_control_implementation(rows: List[Dict[str, Any]]) -> str:
    """ATT&CK → D3FEND → NIST 800-53 control implementation guide."""
    top = _top_techniques(rows, top_n=10)
    if not top:
        return "No ATT&CK technique mappings found. Apply vendor patches per the patch tracking table."
    lines: List[str] = []
    for rank, (aid, cnt, meta) in enumerate(top, 1):
        tname   = meta.get("name", aid)
        tactics = ", ".join(meta.get("tactics", [])) or "Unknown"
        d3fend  = meta.get("d3fend", [])
        nist    = meta.get("nist", [])
        atk_url = f"https://attack.mitre.org/techniques/{aid.replace('.','/')}/"
        lines.append(f"## {rank}. {tname} ({aid})")
        lines.append(f"- **Observed in:** {cnt} CVE{'s' if cnt != 1 else ''} in this scan")
        lines.append(f"- **ATT&CK Tactics:** {tactics}")
        lines.append(f"- **ATT&CK Reference:** {atk_url}")
        lines.append("")
        if d3fend:
            lines.append("### D3FEND Countermeasures — Implementation Steps")
            for cm in d3fend:
                steps = _D3FEND_IMPL.get(cm) or _D3FEND_GENERIC
                d3f_url = f"https://d3fend.mitre.org/technique/d3f:{cm.replace(' ','')}/"
                lines.append(f"**{cm}** — [D3FEND reference]({d3f_url})")
                for i, step in enumerate(steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")
        else:
            lines.append("### D3FEND Countermeasures")
            lines.append("- No specific D3FEND mappings for this technique. Refer to https://d3fend.mitre.org")
            lines.append("")
        if nist:
            lines.append("### NIST SP 800-53 Control Implementation")
            lines.append("| Control | Description | Implementation Note | Reference |")
            lines.append("|---|---|---|---|")
            for ctrl in nist:
                ctrl_id  = ctrl.split()[0] if ctrl.split() else ctrl
                note     = _NIST_IMPL.get(ctrl_id, "Refer to NIST SP 800-53 Rev 5.")
                nist_url = f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={ctrl_id}"
                lines.append(f"| {ctrl_id} | {ctrl} | {note} | {nist_url} |")
            lines.append("")
        else:
            lines.append("### NIST SP 800-53 Controls")
            lines.append("- No NIST control mappings available for this technique.")
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines).strip()


def build_defensive_report(
    all_rows: List[Dict[str, Any]],
    report_title: str = "Technical Security Assessment Report",
) -> str:
    """
    Comprehensive Technical Security Assessment for security engineers, ISSOs,
    SOC analysts, RMF reviewers, vulnerability management teams, and technical leadership.
    Suitable for RMF evidence packages, POA&M development, and security review boards.
    """
    import datetime

    logo_b64  = _load_logo_b64()
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    total_cves    = len(all_rows)
    sev_counts    = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "OTHER": 0}
    kev_total     = 0
    expl_total    = 0
    confirmed_total = 0
    max_risk      = 0.0
    epss_values: List[float] = []

    for r in all_rows:
        sev = str(r.get("CVSS Severity", "") or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["OTHER"] += 1
        if str(r.get("Known Exploited Vulnerability", "")).upper() == "YES":
            kev_total += 1
        if str(r.get("Public Exploit", "")).upper() == "YES":
            expl_total += 1
        if str(r.get("Version Confirmed", "")).upper() == "YES":
            confirmed_total += 1
        rs = _to_float(r.get("Risk Score", 0))
        if rs > max_risk:
            max_risk = rs
        epss_val = _epss_float(r.get("EPSS Score", 0))
        if epss_val > 0:
            epss_values.append(epss_val)

    gn_active_total = sum(
        1 for r in all_rows
        if _THREAT_INTEL_CACHE.get(r.get("CVE ID", ""), {}).get("greynoise", {}).get("noise")
    )
    cwe_counter: Counter = Counter()
    for r in all_rows:
        for cwe in _split_multi(r.get("CWE", "")):
            cwe_counter[cwe] += 1

    top5  = _top_techniques(all_rows, top_n=5)
    top10 = _top_techniques(all_rows, top_n=10)

    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        key = (str(row.get("Software Name", "")).strip(), str(row.get("Software Version", "")).strip())
        grouped[key].append(row)
    sw_count = len(grouped)

    # TOC
    sw_toc_items = "".join(
        f'<li><a href="#{re.sub(r"[^a-z0-9]+", "-", f"{n} {v}".lower()).strip("-")}">'
        f'{html.escape(n)} {html.escape(v)}</a></li>'
        for (n, v) in sorted(grouped.keys(), key=lambda x: x[0].lower())
    )
    toc_html = (
        '<h2>Contents</h2><ul>'
        '<li><a href="#1-executive-technical-summary">1. Executive Technical Summary</a></li>'
        '<li><a href="#2-asset-and-system-overview">2. Asset and System Overview</a></li>'
        '<li><a href="#3-severity-distribution-and-risk-scoring">3. Severity Distribution and Risk Scoring</a></li>'
        '<li><a href="#4-vulnerability-chaining-and-attack-path-analysis">4. Vulnerability Chaining and Attack Path Analysis</a></li>'
        '<li><a href="#5-detailed-cve-analysis">5. Detailed CVE Analysis</a>'
        f'<ul style="margin-top:4px;padding-left:18px;">{sw_toc_items}</ul></li>'
        '<li><a href="#6-cwe-weakness-distribution">6. CWE Weakness Distribution</a></li>'
        '<li><a href="#7-mitre-attck-technique-coverage">7. MITRE ATT&amp;CK Technique Coverage</a></li>'
        '<li><a href="#8-kev-and-epss-priority-analysis">8. KEV / EPSS Priority Analysis</a></li>'
        '<li><a href="#9-threat-scenario-library">9. Threat Scenario Library</a></li>'
        '<li><a href="#10-detection-engineering-recommendations">10. Detection Engineering Recommendations</a></li>'
        '<li><a href="#11-mitigation-and-control-implementation">11. Mitigation and Control Implementation</a></li>'
        '<li><a href="#12-defensive-architecture-considerations">12. Defensive Architecture Considerations</a></li>'
        '<li><a href="#13-security-control-gaps">13. Security Control Gaps</a></li>'
        '<li><a href="#14-recommended-remediation-prioritization">14. Recommended Remediation Prioritization</a></li>'
        '<li><a href="#15-residual-risk-discussion">15. Residual Risk Discussion</a></li>'
        '</ul>'
    )

    lines: List[str] = []

    # 1. Executive Technical Summary
    lines += [
        "# 1. Executive Technical Summary",
        "",
        f"**Assessment Date:** {scan_date}",
        f"**Systems Assessed:** {sw_count}  |  **Total CVEs Identified:** {total_cves}",
        f"**Maximum Risk Score:** {max_risk:.1f} / 100  |  **Overall Posture:** "
        f"{'CRITICAL' if kev_total > 0 or max_risk >= 80 else 'HIGH' if max_risk >= 60 or sev_counts['CRITICAL'] > 0 else 'MODERATE'}",
        "",
        f"This assessment identified **{total_cves} CVEs** across **{sw_count} software components**, "
        f"with **{sev_counts['CRITICAL']} Critical**, **{sev_counts['HIGH']} High**, "
        f"**{sev_counts['MEDIUM']} Medium**, and **{sev_counts['LOW']} Low** severity findings.",
    ]
    if kev_total > 0:
        lines.append(
            f"**{kev_total} CVE{'s are' if kev_total != 1 else ' is'} listed in the "
            f"[CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**, "
            "confirming active in-the-wild exploitation. These are the highest-priority remediation items regardless of CVSS score."
        )
    if gn_active_total > 0:
        lines.append(
            f"GreyNoise threat intelligence confirms active exploitation activity for **{gn_active_total} CVEs** — "
            "treat these as KEV-equivalent priority."
        )
    if expl_total > 0:
        lines.append(
            f"**{expl_total} CVEs** have publicly available exploit code (ExploitDB, Metasploit, Vulners, or NVD references), "
            "reducing the technical exploitation barrier to script-kiddie level for these findings."
        )
    if confirmed_total > 0:
        lines.append(
            f"**{confirmed_total} CVEs** have been version-confirmed as applicable to the exact deployed version — "
            "confirmed exposures, not speculative CPE matches."
        )
    lines += ["", "---", ""]

    # 2. Asset / System Overview
    lines += [
        "# 2. Asset and System Overview",
        "",
        "| Software | Version | Publisher | Install Date | CVEs | Critical | High | KEV | Public Exploit | Max Risk | Action |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for (sw_name, sw_ver), sw_rows in sorted(grouped.items(), key=lambda x: x[0][0].lower()):
        crit   = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        high   = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "HIGH")
        kev_c  = sum(1 for r in sw_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        expl_c = sum(1 for r in sw_rows if str(r.get("Public Exploit","")).upper() == "YES")
        max_rs = max((_to_float(r.get("Risk Score",0)) for r in sw_rows), default=0.0)
        pub    = str(sw_rows[0].get("Publisher", "") or "") if sw_rows else ""
        idate  = str(sw_rows[0].get("Install Date", "") or "") if sw_rows else ""
        action = ("PATCH IMMEDIATELY — KEV/CRITICAL" if (kev_c or crit) else
                  "PATCH URGENTLY — HIGH" if high else "SCHEDULE PATCH")
        lines.append(f"| {sw_name} | {sw_ver} | {pub} | {idate} | {len(sw_rows)} | {crit} | {high} | {kev_c} | {expl_c} | {max_rs:.1f} | {action} |")
    lines += ["", "---", ""]

    # 3. Severity Distribution and Risk Scoring
    lines += [
        "# 3. Severity Distribution and Risk Scoring",
        "",
        "| Severity | Count | % of Total |",
        "|---|---|---|",
    ]
    for sev_label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = sev_counts.get(sev_label, 0)
        pct = (cnt / total_cves * 100) if total_cves else 0
        lines.append(f"| {sev_label} | {cnt} | {pct:.1f}% |")
    lines += [
        "",
        f"**Draugr Weighted Risk Score Model** (0–100): CVSS×0.35 + EPSS×0.25 + KEV×0.20 + Public Exploit×0.10 + Version Confirmation×0.10",
        f"- Highest risk score: **{max_risk:.1f}**",
    ]
    if epss_values:
        avg_epss = sum(epss_values) / len(epss_values)
        max_epss = max(epss_values)
        lines.append(f"- EPSS range: {min(epss_values)*100:.2f}% – {max_epss*100:.2f}%  |  Mean: {avg_epss*100:.2f}%")

    # CVE × Software severity heatmap
    _heatmap_svg = _svg_cve_heatmap(grouped)
    if _heatmap_svg:
        lines += [
            "",
            "<div style='overflow-x:auto;margin:20px 0;'>",
            "<p style='font-size:12px;color:#555;margin-bottom:4px;'>"
            "<em>Figure: CVE severity heatmap — rows are top CVEs by risk score, "
            "columns are software components. C=Critical, H=High, M=Medium, L=Low, "
            "grey=not applicable to that component.</em></p>",
            _heatmap_svg,
            "</div>",
            "",
        ]

    # Patch age analysis
    age_entries: List[int] = []
    overdue_kev: List[Dict[str, Any]] = []
    overdue_crit: List[Dict[str, Any]] = []
    for r in all_rows:
        pa = str(r.get("Patch Age (Days)", "") or "")
        try:
            age_int = int(pa)
            age_entries.append(age_int)
            if age_int > 30 and str(r.get("Known Exploited Vulnerability","")).upper() == "YES":
                overdue_kev.append(r)
            if age_int > 90 and str(r.get("CVSS Severity","")).upper() == "CRITICAL":
                overdue_crit.append(r)
        except ValueError:
            pass

    if age_entries:
        avg_age = sum(age_entries) / len(age_entries)
        max_age = max(age_entries)
        lines += [
            "",
            "**Patch Age Analysis** (based on inventory install dates):",
            "",
            f"- Average days since install across all affected CVEs: **{avg_age:.0f} days**",
            f"- Maximum days since install: **{max_age} days**",
        ]
        if overdue_kev:
            lines.append(
                f"- **{len(overdue_kev)} KEV-listed CVE(s)** present on systems installed >30 days ago "
                "— these represent confirmed exploitation risk on aged deployments."
            )
        if overdue_crit:
            lines.append(
                f"- **{len(overdue_crit)} Critical CVE(s)** present on systems installed >90 days ago "
                "— unpatched critical findings on long-running deployments represent elevated residual risk."
            )
    lines += ["", "---", ""]

    # 4. Vulnerability Chaining and Attack Path Analysis
    lines += [
        "# 4. Vulnerability Chaining and Attack Path Analysis",
        "",
        "The following multi-stage attack paths were identified. Chains represent scenarios where "
        "multiple CVEs compound to achieve outcomes beyond their individual severity ratings.",
        "",
    ]
    any_chain = False
    for (sw_name, sw_ver), sw_rows in sorted(grouped.items(), key=lambda x: x[0][0].lower()):
        sw_rows_s = sorted(sw_rows, key=lambda r: _to_float(r.get("Risk Score", 0)), reverse=True)
        chains = _cve_chain_analysis(sw_rows_s)
        if chains:
            any_chain = True
            lines.append(f"### {sw_name} {sw_ver}")
            for ch in chains:
                lines.append(f"- {ch}")
            lines.append("")
    if not any_chain:
        lines.append("No multi-stage vulnerability chains were identified. Individual CVEs should still be assessed for standalone exploitation potential.")
        lines.append("")
    lines += ["---", ""]

    # 5. Detailed CVE Analysis
    lines += [
        "# 5. Detailed CVE Analysis",
        "",
        "Findings are ordered by risk score (descending) within each software component.",
        "",
    ]
    for (sw_name, sw_ver), sw_rows in sorted(grouped.items(), key=lambda x: x[0][0].lower()):
        sw_rows_s = sorted(sw_rows, key=lambda r: _to_float(r.get("Risk Score", 0)), reverse=True)
        crit  = sum(1 for r in sw_rows_s if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        high  = sum(1 for r in sw_rows_s if str(r.get("CVSS Severity","")).upper() == "HIGH")
        kev_c = sum(1 for r in sw_rows_s if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        max_rs = max((_to_float(r.get("Risk Score",0)) for r in sw_rows_s), default=0.0)
        lines.append(f"## {sw_name} {sw_ver}")
        lines.append(f"CVEs: {len(sw_rows_s)}  |  Critical: {crit}  |  High: {high}  |  KEV: {kev_c}  |  Max Risk Score: {max_rs:.1f}")
        lines.append("")
        for r in sw_rows_s:
            lines.extend(_format_cve_engineering(r, sw_name))
    lines += ["---", ""]

    # 6. CWE Weakness Distribution
    lines += [
        "# 6. CWE Weakness Distribution",
        "",
        "High-frequency CWEs indicate systemic coding or architectural deficiencies across the assessed components.",
        "",
        "| CWE | Weakness Class | Count | Architectural Risk |",
        "|---|---|---|---|",
    ]
    for cwe, cnt in cwe_counter.most_common(15):
        cwe_num   = cwe.replace("CWE-", "")
        cwe_url   = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        short     = _CWE_TECHNICAL_IMPACT.get(cwe, "See CWE reference.")
        short     = short.split("—")[0].strip() if "—" in short else short[:80]
        arch_flag = "Yes — design remediation required" if cwe in _ARCH_RISK_CWES else "No"
        lines.append(f"| [{cwe}]({cwe_url}) | {short} | {cnt} | {arch_flag} |")
    lines += ["", "---", ""]

    # 7. ATT&CK Technique Coverage
    lines += [
        "# 7. MITRE ATT&CK Technique Coverage",
        "",
        f"Technique mapping derived from CWE→CAPEC→ATT&CK correlation across all {total_cves} CVEs.",
        "",
        "| Rank | Technique | Name | CVE Count | Tactics | Reference |",
        "|---|---|---|---|---|---|",
    ]
    for rank, (aid, cnt, meta) in enumerate(top10, 1):
        tname   = meta.get("name", aid)
        tactics = ", ".join(meta.get("tactics", [])) or "—"
        atk_url = f"https://attack.mitre.org/techniques/{aid.replace('.','/')}/"
        lines.append(f"| {rank} | {aid} | {tname} | {cnt} | {tactics} | {atk_url} |")
    lines += [
        "",
        "Detection engineering should prioritize building or validating detection rules for each "
        "technique in rank order. See Section 10 for per-technique detection guidance.",
        "",
        "---",
        "",
    ]

    # 8. KEV / EPSS Priority Analysis
    lines += ["# 8. KEV / EPSS Priority Analysis", ""]
    kev_rows = sorted(
        [r for r in all_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES"],
        key=lambda r: _to_float(r.get("Risk Score",0)), reverse=True
    )
    if kev_rows:
        lines += [
            f"## CISA KEV-Listed CVEs ({len(kev_rows)})",
            "",
            "CISA BOD 22-01 mandates remediation of KEV-listed vulnerabilities for federal agencies. "
            "These represent the highest-confidence exploitation risk in this scan.",
            "",
            "| CVE ID | Software | CVSS | Risk Score | EPSS | KEV Due Date | NVD |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in kev_rows:
            cid2    = r.get("CVE ID", "")
            sw2     = r.get("Software Name", "")
            cvss2   = f"{r.get('CVSS Base Score','N/A')} ({r.get('CVSS Severity','')})"
            rs2     = r.get("Risk Score", "")
            epss2   = r.get("EPSS Score", "")
            due     = r.get("kev_due_date", "") or "—"
            nvd2    = r.get("NVD URL","") or f"https://nvd.nist.gov/vuln/detail/{cid2}"
            lines.append(f"| {cid2} | {sw2} | {cvss2} | {rs2} | {epss2} | {due} | {nvd2} |")
        lines.append("")
    else:
        lines += ["No CISA KEV-listed CVEs identified.", ""]

    epss_rows = sorted(
        [r for r in all_rows if _epss_float(r.get("EPSS Score",0)) > 0],
        key=lambda r: _epss_float(r.get("EPSS Score",0)), reverse=True
    )[:10]
    if epss_rows:
        lines += [
            "## Highest EPSS Probability CVEs (Top 10)",
            "",
            "EPSS scores reflect the 30-day in-the-wild exploitation probability (FIRST.org).",
            "",
            "| CVE ID | Software | EPSS | CVSS | KEV | Public Exploit |",
            "|---|---|---|---|---|---|",
        ]
        for r in epss_rows:
            cid3   = r.get("CVE ID", "")
            sw3    = r.get("Software Name", "")
            epss3  = r.get("EPSS Score", "")
            cvss3  = f"{r.get('CVSS Base Score','N/A')} ({r.get('CVSS Severity','')})"
            kev3   = "Yes" if str(r.get("Known Exploited Vulnerability","")).upper() == "YES" else "No"
            expl3  = "Yes" if str(r.get("Public Exploit","")).upper() == "YES" else "No"
            lines.append(f"| {cid3} | {sw3} | {epss3} | {cvss3} | {kev3} | {expl3} |")
        lines.append("")
    lines += ["---", ""]

    # 9. Threat Scenario Library
    lines += [
        "# 9. Threat Scenario Library",
        "",
        "Threat scenarios describe realistic adversary courses of action derived from ATT&CK mappings. "
        "Scenarios are technique-scoped to capture patterns across multiple CVEs.",
        "",
    ]
    seen_aids: set = set()
    scenario_num = 0
    for (sw_name, sw_ver), sw_rows in sorted(grouped.items(), key=lambda x: x[0][0].lower()):
        for r in sorted(sw_rows, key=lambda r: _to_float(r.get("Risk Score", 0)), reverse=True):
            for atk in _split_multi(r.get("ATT&CK Techniques", "")):
                m = re.match(r"^([A-Z0-9.]+)\s*\((.*?)\)$", atk)
                if m:
                    aid, aname = m.group(1), m.group(2)
                else:
                    aid, aname = atk, atk
                if aid and aid not in seen_aids:
                    seen_aids.add(aid)
                    scenario_num += 1
                    cid = r.get("CVE ID","")
                    scenario_info = SCENARIOS.get(aid)
                    if scenario_info and scenario_info.get("description"):
                        narrative = scenario_info["description"].format(cve_id=cid, software_name=sw_name)
                    else:
                        narrative = _scenario_template(aid, aname, sw_name, cid)
                    tactics_list = get_tactics(aid)
                    impact_text  = get_impact(aid)
                    atk_url      = f"https://attack.mitre.org/techniques/{aid.replace('.','/')}/"
                    lines.append(f"### Scenario {scenario_num}: [{aname} ({aid})]({atk_url})")
                    lines.append(f"**Affects:** {sw_name} {sw_ver}  |  **Tactic(s):** {', '.join(tactics_list) if tactics_list else '—'}")
                    lines.append(f"**Representative CVE:** {cid}")
                    lines.append("")
                    lines.append(narrative)
                    if impact_text:
                        lines.append(f"**Expected Impact:** {impact_text}")
                    lines.append("")
    if scenario_num == 0:
        lines.append("No ATT&CK-mapped threat scenarios available for the current findings.")
        lines.append("")
    lines += ["---", ""]

    # 10. Detection Engineering Recommendations
    lines += [
        "# 10. Detection Engineering Recommendations",
        "",
        "Detection guidance is organized by ATT&CK technique in frequency order. "
        "Each entry is intended for SIEM rule development, EDR policy configuration, or network monitoring.",
        "",
    ]
    for aid, cnt, meta in top10:
        tname   = meta.get("name", aid)
        atk_url = f"https://attack.mitre.org/techniques/{aid.replace('.','/')}/"
        det_recs = _TECHNIQUE_DETECTION.get(aid, [])
        lines.append(f"### [{tname} ({aid})]({atk_url}) — {cnt} CVE{'s' if cnt != 1 else ''}")
        lines.append(f"**Tactics:** {', '.join(meta.get('tactics', [])) or '—'}")
        lines.append("")
        if det_recs:
            for dr in det_recs:
                lines.append(f"- {dr}")
        else:
            lines.append("- Review the ATT&CK technique page for recommended data sources and detection guidance.")
            lines.append("- Enable relevant Windows Security Event IDs or Linux audit rules for this technique class.")
        lines.append("")
    lines += ["---", ""]

    # 11. Mitigation and Control Implementation
    lines += [
        "# 11. Mitigation and Control Implementation",
        "",
        "ATT&CK technique → D3FEND countermeasure → NIST SP 800-53 Rev 5 control mapping, "
        "ranked by CVE frequency.",
        "",
        _defensive_control_implementation(all_rows),
        "",
        "---",
        "",
    ]

    # 12. Defensive Architecture Considerations
    lines += [
        "# 12. Defensive Architecture Considerations",
        "",
        "Architectural risks identified from the vulnerability and CWE profile of the assessed systems:",
        "",
    ]
    arch_findings: List[str] = []
    network_exposed = sum(1 for r in all_rows if "AV:N" in str(r.get("CVSS Vector","") or "").upper())
    if network_exposed > 0:
        arch_findings.append(
            f"**Network Exposure Surface ({network_exposed} CVEs, AV:N):** These CVEs are exploitable from any "
            "network-connected host. Network segmentation, host-based firewall enforcement, and service exposure "
            "reduction are critical architectural mitigations independent of patch status."
        )
    for cwe, cnt_cwe in cwe_counter.most_common():
        arch_note = _ARCH_RISK_CWES.get(cwe)
        if arch_note and cnt_cwe > 0:
            arch_findings.append(f"**{cwe} ({cnt_cwe} occurrence{'s' if cnt_cwe != 1 else ''}):** {arch_note}")
    if sum(1 for v in epss_values if v >= 0.05) >= 3:
        high_epss_c = sum(1 for v in epss_values if v >= 0.05)
        arch_findings.append(
            f"**High-EPSS Cluster ({high_epss_c} CVEs ≥5% EPSS):** Active adversary tooling development is "
            "indicated. Consider whether architectural alternatives exist for the most critical affected components."
        )
    if cwe_counter.get("CWE-319", 0) + cwe_counter.get("CWE-327", 0) + cwe_counter.get("CWE-295", 0) > 0:
        arch_findings.append(
            "**Insecure Protocol/Cryptographic Risk (CWE-319/327/295):** Enforce TLS 1.2+ with valid "
            "certificate chains across all communication paths. Disable legacy cleartext protocols "
            "(HTTP, FTP, Telnet, SNMPv1/v2) on all affected components."
        )
    if cwe_counter.get("CWE-306", 0) + cwe_counter.get("CWE-287", 0) + cwe_counter.get("CWE-798", 0) > 0:
        arch_findings.append(
            "**Authentication Architecture Deficiency (CWE-306/287/798):** Missing authentication, "
            "authentication bypass, or hard-coded credentials indicate a design-level access control gap. "
            "MFA enforcement, credential vaulting, and Zero Trust architecture principles are required."
        )
    priv_cwes_count = sum(cwe_counter.get(c, 0) for c in ["CWE-269","CWE-862","CWE-863","CWE-276","CWE-732"])
    if priv_cwes_count >= 2:
        arch_findings.append(
            f"**Privilege and Access Control Deficiency ({priv_cwes_count} related CWEs):** Multiple privilege "
            "management weaknesses indicate least-privilege is not consistently enforced. A formal access control "
            "review of service accounts, file system permissions, and API authorization is warranted."
        )
    for af in arch_findings:
        lines.append(f"- {af}")
        lines.append("")
    if not arch_findings:
        lines.append("No systemic architectural risk patterns identified beyond the individual CVE findings.")
        lines.append("")
    lines += ["---", ""]

    # 13. Security Control Gaps
    lines += [
        "# 13. Security Control Gaps",
        "",
        "NIST SP 800-53 Rev 5 control families with the highest frequency of mapping across "
        "the identified CVEs indicate likely implementation gaps:",
        "",
        "| Control | Frequency | Gap Assessment | Implementation Guidance |",
        "|---|---|---|---|",
    ]
    nist_counter: Counter = Counter()
    for r in all_rows:
        for ctrl in _split_multi(r.get("NIST 800-53 Controls", "")):
            ctrl_id = ctrl.split()[0] if ctrl.split() else ctrl
            nist_counter[ctrl_id] += 1
    for ctrl_id, freq in nist_counter.most_common(12):
        note     = _NIST_IMPL.get(ctrl_id, "Refer to NIST SP 800-53 Rev 5 for full guidance.")
        ctrl_url = f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={ctrl_id}"
        gap_note = "High — systematic gap indicated" if freq >= 5 else "Moderate"
        lines.append(f"| [{ctrl_id}]({ctrl_url}) | {freq} CVEs | {gap_note} | {note} |")
    lines += ["", "---", ""]

    # 14. Recommended Remediation Prioritization (POA&M-ready)
    lines += [
        "# 14. Recommended Remediation Prioritization",
        "",
        "POA&M-ready prioritized remediation plan. Items ordered by the Draugr risk model "
        "incorporating CVSS, EPSS, KEV status, exploit availability, and version confirmation.",
        "",
        "## Tier 1 — Emergency (24–72 hours)",
        "",
    ]
    tier1 = sorted(
        [r for r in all_rows if
         str(r.get("Known Exploited Vulnerability","")).upper() == "YES" or
         _THREAT_INTEL_CACHE.get(r.get("CVE ID",""),{}).get("greynoise",{}).get("noise")],
        key=lambda r: _to_float(r.get("Risk Score",0)), reverse=True
    )
    if tier1:
        lines += ["| CVE ID | Software | Risk Score | Rationale |", "|---|---|---|---|"]
        for r in tier1[:10]:
            cid4    = r.get("CVE ID","")
            sw4     = r.get("Software Name","")
            rs4     = r.get("Risk Score","")
            kev4    = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
            rationale = "KEV-listed; active exploitation confirmed" if kev4 else "GreyNoise active exploitation signal"
            nvd4    = r.get("NVD URL","") or f"https://nvd.nist.gov/vuln/detail/{cid4}"
            lines.append(f"| [{cid4}]({nvd4}) | {sw4} | {rs4} | {rationale} |")
        lines.append("")
    else:
        lines += ["No Tier 1 emergency items in this scan.", ""]

    tier1_ids = {r.get("CVE ID","") for r in tier1}
    tier2 = sorted(
        [r for r in all_rows if r.get("CVE ID","") not in tier1_ids and
         (str(r.get("CVSS Severity","")).upper() == "CRITICAL" or
          str(r.get("Public Exploit","")).upper() == "YES")],
        key=lambda r: _to_float(r.get("Risk Score",0)), reverse=True
    )
    lines += ["## Tier 2 — Critical (7 days)", ""]
    if tier2:
        lines += ["| CVE ID | Software | CVSS | Risk Score | Rationale |", "|---|---|---|---|---|"]
        for r in tier2[:15]:
            cid5    = r.get("CVE ID","")
            sw5     = r.get("Software Name","")
            cvss5   = f"{r.get('CVSS Base Score','N/A')} ({r.get('CVSS Severity','')})"
            rs5     = r.get("Risk Score","")
            is_crit = str(r.get("CVSS Severity","")).upper() == "CRITICAL"
            is_expl = str(r.get("Public Exploit","")).upper() == "YES"
            rationale = ("Critical + public exploit" if is_crit and is_expl else
                         "Critical severity" if is_crit else "Public exploit code available")
            nvd5    = r.get("NVD URL","") or f"https://nvd.nist.gov/vuln/detail/{cid5}"
            lines.append(f"| [{cid5}]({nvd5}) | {sw5} | {cvss5} | {rs5} | {rationale} |")
        lines.append("")
    else:
        lines += ["No additional Tier 2 items beyond Tier 1.", ""]

    tier12_ids = tier1_ids | {r.get("CVE ID","") for r in tier2}
    tier3_count = sum(1 for r in all_rows if r.get("CVE ID","") not in tier12_ids and
                      str(r.get("CVSS Severity","")).upper() == "HIGH")
    tier4_count = sum(1 for r in all_rows if r.get("CVE ID","") not in tier12_ids and
                      str(r.get("CVSS Severity","")).upper() not in ("CRITICAL","HIGH"))
    lines += [
        f"## Tier 3 — High Priority (30 days)",
        "",
        f"**{tier3_count} High-severity CVEs** — address via standard change management. See Section 5 for full detail.",
        "",
        f"## Tier 4 — Routine (90 days)",
        "",
        f"**{tier4_count} Medium/Low CVEs** — address through standard vulnerability management programme.",
        "",
        "---",
        "",
    ]

    # 15. Residual Risk Discussion
    lines += [
        "# 15. Residual Risk Discussion",
        "",
        "Upon completion of all remediation activities, the following residual risks persist and "
        "should be documented in the system's risk acceptance framework:",
        "",
    ]
    residual: List[str] = []
    residual.append(
        "**Continuous Disclosure Risk:** New CVEs will be published for the assessed components on an ongoing basis. "
        "Subscribe to vendor security advisories and NVD feeds. A continuous monitoring and patch management programme "
        "is required to maintain an acceptable risk posture beyond the remediation of current findings."
    )
    if sev_counts["MEDIUM"] + sev_counts["LOW"] > 0:
        residual.append(
            f"**Lower-Severity Vulnerability Accumulation ({sev_counts['MEDIUM']} Medium, {sev_counts['LOW']} Low):** "
            "These CVEs are not individually critical but can be chained with future zero-days or other vulnerabilities. "
            "Deferred remediation increases aggregate risk over time."
        )
    if total_cves > confirmed_total and confirmed_total > 0:
        unconfirmed = total_cves - confirmed_total
        residual.append(
            f"**{unconfirmed} Unconfirmed Version Matches:** Matched via CPE lookup but not version-confirmed against "
            "the exact deployed build. Manual validation by the system owner is required to determine definitive applicability."
        )
    residual.append(
        "**Control Effectiveness Uncertainty:** D3FEND countermeasures and NIST 800-53 controls are documented as "
        "recommendations; their implementation state was not validated by this assessment. A configuration audit or "
        "purple-team exercise is recommended to confirm correct deployment."
    )
    residual.append(
        "**Third-Party and Supply Chain Exposure:** This assessment covers identified software components but not their "
        "transitive dependencies, runtime environments, or third-party integrations. Vulnerabilities in these layers "
        "may create indirect exposure to the assessed systems."
    )
    if kev_total > 0:
        residual.append(
            "**Indicator of Compromise Review Required:** Given the presence of KEV-listed CVEs, a threat-hunting exercise "
            "should be conducted to determine whether exploitation may have already occurred prior to remediation. Review "
            "authentication logs, network flow data, and endpoint telemetry for indicators consistent with the ATT&CK "
            "techniques identified in Section 7."
        )
    for r_item in residual:
        lines.append(f"- {r_item}")
        lines.append("")

    # ── ICS / OT ATT&CK section (appended if any ICS-relevant findings) ──
    if HAS_ICS:
        ics_section = ics_summary_section(all_rows)
        if ics_section:
            lines += ["---", "", ics_section]

    # ── Plugin report sections ─────────────────────────────────────────
    if HAS_PLUGINS:
        plugin_md = collect_report_sections(all_rows)
        if plugin_md:
            lines += ["---", "", plugin_md]

    body_md = "\n".join(lines).strip() + "\n"
    return _wrap_html_report(
        title=report_title,
        body_md=body_md,
        logo_b64=logo_b64,
        subtitle="Technical Security Assessment — Engineering & RMF Audience",
        toc_html=toc_html,
    )



# ======================================================================
#  RED TEAM REPORT  – Target prioritisation and exploitation paths
# ======================================================================

def _redteam_target_score(sw_rows: List[Dict[str, Any]]) -> float:
    """
    Compute a composite 'target attractiveness' score for a software item.

    Model: best single CVE risk score as the base, then software-level
    bonuses for exploitation readiness and severity depth.

    Base (0–100):
        Highest individual CVE risk score.

    Flat bonuses:
        +25  any KEV-listed CVE (active exploitation documented)
        +22  any CVE has active GreyNoise exploitation traffic (confirmed live threat)
        +20  any CVE has public exploit code
        +15  any version-confirmed Critical CVE exists
        +10  any version-confirmed High CVE exists (if no confirmed Critical)
        +5   per additional KEV beyond the first (capped at 3 extras → +15 max)
        +3   per additional GreyNoise-active CVE beyond the first (capped at +9 max)

    EPSS bonus (0–15):
        Highest single EPSS score × 15

    Critical/High count bonus (capped at +10):
        +1 per Critical CVE, +0.5 per High CVE, max 10 points

    Rationale for GreyNoise placement:
        GreyNoise active (+22) sits between KEV (+25) and public exploit (+20).
        KEV is the gold standard — it requires CISA confirmation of active exploitation.
        GreyNoise active is real observed traffic but not formally catalogued, so it
        ranks just below KEV. A public exploit sitting on ExploitDB but not yet being
        fired in the wild is ranked lower than both.
    """
    if not sw_rows:
        return 0.0

    # --- Base: highest single CVE risk score ---
    base = max(_to_float(r.get("Risk Score", 0)) for r in sw_rows)

    # --- Software-level flags ---
    kev_count  = sum(1 for r in sw_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
    has_exploit = any(str(r.get("Public Exploit","")).upper() == "YES" for r in sw_rows)
    crit_confirmed = any(
        str(r.get("CVSS Severity","")).upper() == "CRITICAL"
        and str(r.get("Version Confirmed","")).upper() == "YES"
        for r in sw_rows
    )
    high_confirmed = any(
        str(r.get("CVSS Severity","")).upper() == "HIGH"
        and str(r.get("Version Confirmed","")).upper() == "YES"
        for r in sw_rows
    )
    best_epss  = max((_epss_float(r.get("EPSS Score", 0)) for r in sw_rows), default=0.0)
    crit_count = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
    high_count = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "HIGH")

    # --- GreyNoise active exploitation count ---
    gn_active_count = sum(
        1 for r in sw_rows
        if _THREAT_INTEL_CACHE.get(r.get("CVE ID",""), {}).get("greynoise", {}).get("noise")
    )

    # --- Bonuses ---
    bonus = 0.0
    if kev_count:
        bonus += 25
        bonus += min((kev_count - 1) * 5, 15)      # +5 per extra KEV, capped at +15
    if gn_active_count:
        bonus += 22
        bonus += min((gn_active_count - 1) * 3, 9) # +3 per extra GN-active, capped at +9
    if has_exploit:
        bonus += 20
    if crit_confirmed:
        bonus += 15
    elif high_confirmed:
        bonus += 10
    bonus += best_epss * 15
    bonus += min(crit_count * 1.0 + high_count * 0.5, 10)

    return round(base + bonus, 1)


def _redteam_target_table(all_rows: List[Dict[str, Any]]) -> str:
    """Ranked table of software targets by exploitability score."""
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for r in all_rows:
        key = (str(r.get("Software Name","")).strip(), str(r.get("Software Version","")).strip())
        grouped[key].append(r)

    ranked = sorted(
        grouped.items(),
        key=lambda kv: _redteam_target_score(kv[1]),
        reverse=True,
    )

    lines = [
        "| Rank | Software | Version | Target Score | CVEs | Critical | KEV | GN Active | Public Exploits | Highest EPSS | Confirmed |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for rank, ((name, ver), sw_rows) in enumerate(ranked, 1):
        ts    = _redteam_target_score(sw_rows)
        total = len(sw_rows)
        crit  = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        kev   = sum(1 for r in sw_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        expl  = sum(1 for r in sw_rows if str(r.get("Public Exploit","")).upper() == "YES")
        conf  = sum(1 for r in sw_rows if str(r.get("Version Confirmed","")).upper() == "YES")
        epss  = max((_epss_float(r.get("EPSS Score", 0)) for r in sw_rows), default=0.0)
        gn    = sum(1 for r in sw_rows
                    if _THREAT_INTEL_CACHE.get(r.get("CVE ID",""), {}).get("greynoise", {}).get("noise"))
        gn_str = f"⚠ {gn}" if gn else "—"
        lines.append(f"| {rank} | {name} | {ver} | {ts:.1f} | {total} | {crit} | {kev} | {gn_str} | {expl} | {epss:.3f} | {conf} |")
    return "\n".join(lines)


def _redteam_attack_chains(all_rows: List[Dict[str, Any]], otx_results: Optional[Dict[str, Any]] = None) -> str:
    """
    Per-target: entry vectors, ATT&CK kill-chain mapping, OTX intel,
    and recommended exploitation approach.
    """
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for r in all_rows:
        key = (str(r.get("Software Name","")).strip(), str(r.get("Software Version","")).strip())
        grouped[key].append(r)

    ranked = sorted(
        grouped.items(),
        key=lambda kv: _redteam_target_score(kv[1]),
        reverse=True,
    )

    lines: List[str] = []
    for rank, ((name, ver), sw_rows) in enumerate(ranked, 1):
        sw_rows_sorted = sorted(sw_rows, key=lambda r: _to_float(r.get("Risk Score",0)), reverse=True)
        ts     = _redteam_target_score(sw_rows)
        crit   = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        high   = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "HIGH")
        kev    = sum(1 for r in sw_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        expl_rows = [r for r in sw_rows if str(r.get("Public Exploit","")).upper() == "YES"]

        lines.append(f"## Target {rank}: {name} {ver}  (Score: {ts:.1f})")
        lines.append("")
        lines.append(f"- **Total CVEs:** {len(sw_rows)}  |  Critical: {crit}  |  High: {high}")
        lines.append(f"- **KEV-listed CVEs:** {kev}")
        lines.append(f"- **CVEs with public exploit code:** {len(expl_rows)}")
        lines.append("")

        # Entry vectors — highest-risk CVEs with exploits or KEV
        priority_cves = [
            r for r in sw_rows_sorted
            if str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
            or str(r.get("Public Exploit","")).upper() == "YES"
        ][:5]
        if not priority_cves:
            priority_cves = sw_rows_sorted[:3]

        lines.append("### Recommended Entry Vectors")
        for r in priority_cves:
            cid   = r.get("CVE ID","")
            score = r.get("CVSS Base Score","N/A")
            sev   = r.get("CVSS Severity","")
            rs    = r.get("Risk Score","")
            conf  = r.get("Version Confirmed","")
            kev_f = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
            expl_f= str(r.get("Public Exploit","")).upper() == "YES"
            epss  = _epss_float(r.get("EPSS Score", 0))
            src   = r.get("Exploit Sources","") or "None identified"
            desc  = str(r.get("Description","") or "").strip()
            flags = []
            if kev_f:  flags.append("KEV")
            if expl_f: flags.append("PUBLIC EXPLOIT")
            if conf.upper() == "YES": flags.append("VERSION CONFIRMED")
            flag_str = " | ".join(flags) if flags else "Standard CVE"

            lines.append(f"#### {cid}  [{flag_str}]")
            lines.append(f"- CVSS: {score} ({sev})  |  Risk Score: {rs}  |  EPSS: {epss:.3f}")
            for es in (src.split("; ") if src != "None identified" else ["None identified"]):
                lines.append(f"- Exploit Source: {es.strip()}")
            lines.append(f"- Brief: {desc}")
            lines.append(f"- NVD: {r.get('NVD URL','')}")
            lines.append("")

        # ATT&CK kill-chain summary for this target
        technique_counter: Counter = Counter()
        tactic_set: set = set()
        for r in sw_rows:
            for t in _split_multi(r.get("ATT&CK Techniques","")):
                technique_counter[t] += 1
            for tac in _split_multi(r.get("ATT&CK Tactics","")):
                tactic_set.add(tac)

        if technique_counter:
            lines.append("### ATT&CK Kill-Chain Coverage")
            if tactic_set:
                lines.append(f"- **Tactics covered:** {', '.join(sorted(tactic_set))}")
            lines.append("")
            lines.append("| Technique | Count | ATT&CK Link |")
            lines.append("|---|---|---|")
            for tech, cnt in technique_counter.most_common(10):
                m = re.match(r"^([A-Z0-9.]+)", tech)
                tid = m.group(1) if m else ""
                url = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/" if tid else ""
                lines.append(f"| {tech} | {cnt} | {url} |")
            lines.append("")

        # CWE exposure classes
        cwe_counter: Counter = Counter()
        for r in sw_rows:
            for c in _split_multi(r.get("CWE","")):
                cwe_counter[c] += 1
        if cwe_counter:
            lines.append("### Vulnerability Classes (CWE)")
            for cwe, cnt in cwe_counter.most_common(5):
                lines.append(f"- {cwe}  ({cnt} CVEs)")
            lines.append("")

        # Exploitation notes
        lines.append("### Operator Notes")
        if kev:
            lines.append(f"- This target has **{kev} KEV-listed CVE(s)** — active exploitation in the wild is documented. Existing weaponised tools likely available.")
        if expl_rows:
            lines.append(f"- **{len(expl_rows)} CVE(s)** have confirmed public exploit code — check Metasploit, ExploitDB, and Vulners for ready-made modules.")
        if crit:
            lines.append(f"- **{crit} Critical CVE(s)** identified — these represent the highest-impact exploitation paths.")

        # OTX per-target block
        if otx_results:
            otx_block = _redteam_otx_target_block(name, ver, otx_results, sw_rows_sorted)
            if otx_block:
                lines.append("")
                lines.append(otx_block)

        lines.append("- Review exploit sources in the entry vectors above; confirm applicability to the exact version in scope.")
        lines.append("- Cross-reference with threat-intelligence for any APT or ransomware group known to target this product.")
        lines.append(f"- ATT&CK Navigator layer recommended: map the techniques above to assess detection gaps before engagement.")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines).strip()



def _redteam_otx_target_block(
    software_name: str,
    software_version: str,
    otx_results: Dict[str, Any],
    sw_rows: List[Dict[str, Any]],
) -> str:
    """
    Threat intelligence block for a single red team target (Section 2).
    Draws from CIRCL CVE Search and GreyNoise Community data stored in
    _THREAT_INTEL_CACHE, cross-referenced with the scan risk scores.
    """
    key = f"{software_name} {software_version}".strip()
    data = otx_results.get(key)
    if not data:
        return ""

    cve_counts = data.get("cve_pulse_counts", {})
    if not cve_counts:
        return ""

    lines: List[str] = ["### Threat Intelligence (CIRCL / GreyNoise)"]

    active_cves = {cid: s for cid, s in cve_counts.items()
                   if _THREAT_INTEL_CACHE.get(cid, {}).get("greynoise", {}).get("noise")}

    if active_cves:
        lines.append(
            f"\u26a0 **{len(active_cves)} CVE(s)** affecting **{software_name} {software_version}** "
            "show active in-the-wild exploitation traffic (GreyNoise)."
        )
    lines.append(
        f"CIRCL CVE Search returned enrichment data for **{len(cve_counts)}** CVE(s) in this target."
    )
    lines.append("")

    cve_risk_map = {r.get("CVE ID", ""): r for r in sw_rows}
    sorted_cves  = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    lines.append("**CVE Threat Activity (sorted by enrichment score):**")
    lines.append("")
    lines.append("| CVE ID | Activity Score | GreyNoise | Risk Score | CVSS | Public Exploit |")
    lines.append("|---|---|---|---|---|---|")
    for cve_id, score in sorted_cves:
        row      = cve_risk_map.get(cve_id, {})
        rs       = row.get("Risk Score", "\u2014")
        cvss     = row.get("CVSS Base Score", "\u2014")
        expl     = "Yes" if str(row.get("Public Exploit","")).upper() == "YES" else "No"
        gn       = _THREAT_INTEL_CACHE.get(cve_id, {}).get("greynoise", {})
        gn_label = "\u26a0 Active" if gn.get("noise") else ("Known scanner" if gn.get("riot") else "\u2014")
        lines.append(f"| {cve_id} | {score} | {gn_label} | {rs} | {cvss} | {expl} |")
    lines.append("")

    capec_seen: set = set()
    capec_lines: List[str] = []
    for cve_id, _ in sorted_cves[:5]:
        circl = _THREAT_INTEL_CACHE.get(cve_id, {}).get("circl", {})
        for c in (circl.get("capec") or [])[:2]:
            cid_str = f"CAPEC-{c.get('id','')} {c.get('name','')}".strip()
            if cid_str not in capec_seen:
                capec_seen.add(cid_str)
                capec_lines.append(f"  - {cid_str} (via {cve_id})")
    if capec_lines:
        lines.append("**CAPEC Attack Patterns (from CIRCL enrichment):**")
        lines.extend(capec_lines)
        lines.append("")

    if active_cves:
        lines.append(
            "> GreyNoise-active CVEs have confirmed scanning/exploitation traffic. "
            "Weaponised tooling is likely available or in active use — prioritise these as "
            "primary entry vectors regardless of CVSS score."
        )
        lines.append("")

    return "\n".join(lines)


def _redteam_otx_environment_summary(
    all_rows: List[Dict[str, Any]],
    otx_results: Dict[str, Any],
) -> str:
    """
    Environment-level threat intelligence summary for Section 4 of the red team report.
    Draws from CIRCL / GreyNoise data collected during the scan.
    """
    if not otx_results:
        return "Threat intelligence was not collected for this scan."

    # Aggregate all CVE enrichment scores across targets
    all_cve_counts: Dict[str, int] = {}
    for data in otx_results.values():
        for cve_id, cnt in data.get("cve_pulse_counts", {}).items():
            all_cve_counts[cve_id] = all_cve_counts.get(cve_id, 0) + cnt

    if not all_cve_counts:
        return "No CVE enrichment data was returned from CIRCL or GreyNoise for this scan."

    total_enriched = len(all_cve_counts)
    active_cves    = [cid for cid in all_cve_counts
                      if _THREAT_INTEL_CACHE.get(cid, {}).get("greynoise", {}).get("noise")]
    targets_hit    = len(otx_results)

    lines: List[str] = []
    lines.append(
        f"Threat intelligence enrichment covers **{total_enriched}** CVE(s) across "
        f"**{targets_hit}** scanned software item(s)."
    )
    if active_cves:
        lines.append(
            f"\u26a0 **{len(active_cves)}** CVE(s) show active in-the-wild exploitation "
            "traffic via GreyNoise — these are confirmed live threats."
        )
    lines.append("")

    # Per-target summary table
    lines.append("### Software Targets by Threat Activity")
    lines.append("| Software | CVEs Enriched | GreyNoise Active | Top CVE |")
    lines.append("|---|---|---|---|")
    for key, data in sorted(otx_results.items()):
        cvc = data.get("cve_pulse_counts", {})
        if not cvc:
            continue
        active = sum(1 for cid in cvc
                     if _THREAT_INTEL_CACHE.get(cid, {}).get("greynoise", {}).get("noise"))
        top    = max(cvc, key=cvc.get) if cvc else "—"
        lines.append(f"| {key} | {len(cvc)} | {active} | {top} |")
    lines.append("")

    # Cross-environment CVE table
    cve_risk_map  = {r.get("CVE ID", ""): r for r in all_rows}
    sorted_cves   = sorted(all_cve_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    lines.append("### Highest-Activity CVEs Across All Targets")
    lines.append("| CVE ID | Software | Activity Score | GreyNoise | Risk Score | CVSS | KEV | Public Exploit |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for cve_id, score in sorted_cves:
        row      = cve_risk_map.get(cve_id, {})
        name     = row.get("Software Name", "\u2014")
        rs       = row.get("Risk Score", "\u2014")
        cvss     = row.get("CVSS Base Score", "\u2014")
        kev      = "Yes" if str(row.get("Known Exploited Vulnerability","")).upper() == "YES" else "No"
        expl     = "Yes" if str(row.get("Public Exploit","")).upper() == "YES" else "No"
        gn       = _THREAT_INTEL_CACHE.get(cve_id, {}).get("greynoise", {})
        gn_label = "\u26a0 Active" if gn.get("noise") else ("Scanner" if gn.get("riot") else "\u2014")
        lines.append(f"| {cve_id} | {name} | {score} | {gn_label} | {rs} | {cvss} | {kev} | {expl} |")
    lines.append("")
    lines.append(
        "> CVEs with active GreyNoise signals or high enrichment scores represent confirmed "
        "threat-actor interest. Prioritise these as primary entry vectors — exploitation "
        "infrastructure may already be deployed in the wild."
    )
    lines.append("")

    return "\n".join(lines).strip()


def _redteam_exploit_inventory(all_rows: List[Dict[str, Any]]) -> str:
    """Consolidated table of all CVEs with confirmed exploit code or KEV status."""
    exploit_rows = [
        r for r in all_rows
        if str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
        or str(r.get("Public Exploit","")).upper() == "YES"
    ]
    exploit_rows.sort(key=lambda r: _to_float(r.get("Risk Score",0)), reverse=True)

    if not exploit_rows:
        return "No CVEs with confirmed public exploit code or KEV status were found in this scan."

    lines = [
        "| CVE ID | Software | Ver | CVSS | EPSS | KEV | Exploit Sources | Risk Score | Confirmed |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in exploit_rows:
        cid   = r.get("CVE ID","")
        name  = r.get("Software Name","")
        ver   = r.get("Software Version","")
        cvss  = r.get("CVSS Base Score","")
        epss  = f"{_epss_float(r.get('EPSS Score',0)):.3f}"
        kev   = "YES" if str(r.get("Known Exploited Vulnerability","")).upper() == "YES" else "No"
        src   = r.get("Exploit Sources","") or "NVD refs"
        rs    = r.get("Risk Score","")
        conf  = r.get("Version Confirmed","")
        src_cell = "<br>".join(s.strip() for s in src.split(";") if s.strip())
        lines.append(f"| {cid} | {name} | {ver} | {cvss} | {epss} | {kev} | {src_cell} | {rs} | {conf} |")
    return "\n".join(lines)


def _redteam_high_epss(all_rows: List[Dict[str, Any]]) -> str:
    """Surface CVEs with the highest EPSS scores — statistically most likely to be exploited."""
    scored = [r for r in all_rows if _epss_float(r.get("EPSS Score", 0)) > 0]
    scored.sort(key=lambda r: _epss_float(r.get("EPSS Score", 0)), reverse=True)
    top = scored[:15]

    if not top:
        return "No EPSS scores were returned for CVEs in this scan."

    lines = [
        "EPSS (Exploit Prediction Scoring System) estimates the probability that a CVE will be exploited in the wild within the next 30 days. "
        "CVEs below have the highest exploitation probability in this scan.",
        "",
        "| CVE ID | Software | EPSS Score | EPSS %ile | CVSS | KEV | Public Exploit | NVD |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in top:
        cid   = r.get("CVE ID","")
        name  = r.get("Software Name","")
        epss  = _epss_float(r.get("EPSS Score", 0))
        pctl  = r.get("EPSS Percentile","")
        cvss  = r.get("CVSS Base Score","")
        kev   = "YES" if str(r.get("Known Exploited Vulnerability","")).upper() == "YES" else "No"
        expl  = "YES" if str(r.get("Public Exploit","")).upper() == "YES" else "No"
        url   = r.get("NVD URL","")
        lines.append(f"| {cid} | {name} | {epss:.4f} | {pctl} | {cvss} | {kev} | {expl} | {url} |")
    return "\n".join(lines)


def build_redteam_report(
    all_rows: List[Dict[str, Any]],
    report_title: str = "Red Team Target Report",
    otx_results: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build a red-team-focused report ranking targets by exploitability,
    mapping ATT&CK kill chains, and inventorying available exploit code.
    Engagement Recommendations are Section 1; other sections follow.
    """
    logo_b64 = _load_logo_b64()
    otx_results = otx_results or {}

    import datetime
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    software_set = {str(r.get("Software Name","")).strip() for r in all_rows if r.get("Software Name")}
    kev_total  = sum(1 for r in all_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
    expl_total = sum(1 for r in all_rows if str(r.get("Public Exploit","")).upper() == "YES")
    crit_total = sum(1 for r in all_rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
    high_total = sum(1 for r in all_rows if str(r.get("CVSS Severity","")).upper() == "HIGH")

    total_otx_pulses = sum(
        d.get("pulse_count", 0) for d in otx_results.values() if not d.get("error")
    )

    if kev_total >= 5 or crit_total >= 10:
        threat_level = "CRITICAL — Active exploitation risk; multiple high-value targets present."
    elif kev_total > 0 or expl_total >= 5:
        threat_level = "HIGH — Confirmed weaponised CVEs present; environment is a viable target."
    elif crit_total > 0 or high_total >= 5:
        threat_level = "ELEVATED — Significant attack surface; no confirmed active exploitation."
    else:
        threat_level = "MODERATE — Limited exploit exposure identified."

    # TOC
    toc_html = (
        '<h2>Contents</h2><ul>'
        '<li><a href="#section-1-engagement-recommendations">Section 1 — Engagement Recommendations</a></li>'
        '<li><a href="#section-2-target-priority-ranking">Section 2 — Target Priority Ranking</a></li>'
        '<li><a href="#section-3-per-target-attack-profiles">Section 3 — Per-Target Attack Profiles</a></li>'
        '<li><a href="#section-4-exploit-inventory">Section 4 — Exploit Inventory</a></li>'
        '<li><a href="#section-5-threat-intelligence-summary">Section 5 — Threat Intelligence Summary</a></li>'
        '<li><a href="#section-6-highest-epss-probability-cves">Section 6 — Highest EPSS Probability CVEs</a></li>'
        '</ul>'
    )

    lines: List[str] = [
        "## Red Team Report — Purpose and Scope",
        "",
        "This report is intended for red team operators, penetration testers, and threat-intelligence "
        "analysts. It identifies the most attractive targets in the scanned environment, ranks them by "
        "exploitability, and maps available attack paths using the "
        "[MITRE ATT&CK framework](https://attack.mitre.org/ \"ATT&CK\").",
        "",
        "> **HANDLING: RESTRICTED** — This report contains information about exploitable vulnerabilities "
        "in production systems. Distribute only to authorised personnel.",
        "",
        f"- Scan date: {scan_date}",
        f"- Software items assessed: {len(software_set)}",
        f"- Total CVEs: {len(all_rows)}  |  Critical: {crit_total}  |  High: {high_total}",
        f"- KEV-listed (active exploitation documented): {kev_total}  — [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
        f"- CVEs with public exploit code: {expl_total}",
        f"- **Overall environment threat level: {threat_level}**",
        "",
        "---",
        "",
        "# Section 1 — Engagement Recommendations",
        "",
        "Based on the scan findings, the following engagement priorities are recommended:",
        "",
        "1. **Begin with KEV-listed and public-exploit CVEs** — these have the lowest technical barrier and highest confidence of exploitation success. See Section 4 for the full exploit inventory.",
        "2. **Target the highest-scoring software items first** (see Section 2) — they offer the best risk/return for initial access.",
        "3. **Cross-reference threat intelligence** (Sections 3 and 5) — CVEs with active GreyNoise signals have confirmed in-the-wild exploitation; established adversary tooling is likely available.",
        "4. **Map the [ATT&CK](https://attack.mitre.org/) techniques** identified in Section 3 to your toolset; look for gaps in defender coverage to exploit.",
        f"5. **Chain vulnerabilities where possible** — privilege-escalation CVEs ([T1068](https://attack.mitre.org/techniques/T1068/)) after initial-access CVEs ([T1190](https://attack.mitre.org/techniques/T1190/)) are a common and effective pattern.",
        "6. **Cross-reference with CTI** — search VirusTotal, Shodan, and threat-intel feeds for IoCs related to the KEV entries; determine if the environment is already compromised.",
        "7. **Validate EPSS top-10 CVEs** (Section 6) — high EPSS scores indicate adversary attention; these may have undisclosed or newly published PoC code.",
        "8. **Document all findings** in your engagement management platform and align with the Rules of Engagement before exploitation.",
        "",
        "---",
        "",
        "# Section 2 — Target Priority Ranking",
        "",
        "Targets are ranked by a composite score using the highest single CVE risk score "
        "as the base, with flat bonuses for KEV status, public exploit availability, "
        "version-confirmed severity, and EPSS exploitation probability. Volume of CVEs "
        "does not inflate the score — a target with one KEV-listed critical CVE will "
        "outscore a target with hundreds of low-quality CVEs.",
        "",
        "**Scoring breakdown:** Base = highest CVE risk score (0–100) · +25 any KEV · "
        "+5 per additional KEV (cap +15) · +20 any public exploit · +15 version-confirmed "
        "Critical · +10 version-confirmed High · EPSS best × 15 · severity depth bonus (cap +10).",
        "",
        _redteam_target_table(all_rows),
        "",
        "---",
        "",
        "# Section 3 — Per-Target Attack Profiles",
        "",
        "Each target is profiled with recommended entry vectors, ATT&CK kill-chain coverage, "
        "threat intelligence, vulnerability class breakdown, and operator notes.",
        "",
        _redteam_attack_chains(all_rows, otx_results=otx_results),
        "",
        "---",
        "",
        "# Section 4 — Exploit Inventory",
        "",
        "All CVEs in this scan that have confirmed public exploit code or are listed in the "
        "[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). "
        "These represent the most immediately actionable exploitation opportunities.",
        "",
        _redteam_exploit_inventory(all_rows),
        "",
        "---",
        "",
        "# Section 5 — Threat Intelligence Summary",
        "",
        "Environment-level view of threat activity from CIRCL CVE Search and GreyNoise Community. "
        "CVEs with active GreyNoise signals represent confirmed in-the-wild exploitation — "
        "treat these as highest-priority entry vectors for the engagement.",
        "",
        _redteam_otx_environment_summary(all_rows, otx_results),
        "",
        "---",
        "",
        "# Section 6 — Highest EPSS Probability CVEs",
        "",
        "The [EPSS (Exploit Prediction Scoring System)](https://www.first.org/epss/) scores below "
        "indicate the probability of exploitation in the wild within 30 days.",
        "",
        _redteam_high_epss(all_rows),
        "",
    ]

    body_md = "\n".join(lines)
    return _wrap_html_report(
        title=report_title,
        body_md=body_md,
        logo_b64=logo_b64,
        subtitle="Target Prioritisation & Attack Path Analysis",
        toc_html=toc_html,
    )

