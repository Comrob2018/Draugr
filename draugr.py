"""
Draugr — PyQt6 desktop GUI tool that checks software against the NVD
database, cross‑references the CISA Known Exploited Vulnerabilities catalog,
pulls EPSS scores, checks for public exploits, and computes a weighted risk
score per CVE. Exports results to CSV.

Requirements:
    pip install PyQt6 requests packaging

Usage:
1. Prepare a software list file (see sample_software_list.txt format).
2. Optionally download the CISA KEV JSON from:
   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
3. Optionally create a cpe_mappings.json file (see CPE MAPPING section below).
4. Run:
   python cve_scanner.py

CPE MAPPING FILE (optional — cpe_mappings.json):
    A JSON object that pins product names to exact CPE vendor:product pairs.
    This bypasses the heuristic keyword search and dramatically reduces false
    positives. Example:

    {
        "apache tomcat":  "apache:tomcat",
        "openssl":        "openssl:openssl",
        "microsoft edge": "microsoft:edge_chromium",
        "7-zip":          "igor_pavlov:7-zip"
    }

    Keys are matched case‑insensitively against the "name" column in your
    software list. The value is the CPE "vendor:product" portion used to
    build a cpeName filter like  cpe:2.3:a:VENDOR:PRODUCT:*:*:*:*:*:*:*:*.
"""

# ----------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------
import base64
import csv
import datetime
import hashlib
import html
import json
import os
import re
import sys
import time
import sqlite3
import argparse
from collections import defaultdict, Counter
from pathlib import Path
from packaging.version import Version, InvalidVersion
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote_plus
from resources.mitre_attack_scenarios import TECHNIQUE_SCENARIOS as SCENARIOS, get_tactics, get_impact

# Draugr companion modules (imported with fallback so headless CLI still works)
try:
    from draugr_themes import get_theme, set_theme, load_saved_theme, qt_stylesheet, t as _t, THEMES, report_css_overrides
    HAS_THEMES = True
    load_saved_theme()
except ImportError:
    HAS_THEMES = False
    def _t(k, fb="#888"): return fb  # type: ignore

try:
    from draugr_sbom import export_sbom
    HAS_SBOM = True
except ImportError:
    HAS_SBOM = False

try:
    from draugr_plugins import load_plugins, apply_enrich_row, apply_score_modifier, apply_on_scan_complete, collect_report_sections, ensure_plugins_dir, get_loaded_plugins, get_load_errors
    HAS_PLUGINS = True
except ImportError:
    HAS_PLUGINS = False
    def apply_enrich_row(r): return r           # type: ignore
    def apply_score_modifier(r, s): return s    # type: ignore
    def apply_on_scan_complete(rows): return rows  # type: ignore
    def collect_report_sections(rows): return ""   # type: ignore

try:
    from draugr_ics import enrich_row_with_ics, ics_summary_section, is_ics_relevant
    HAS_ICS = True
except ImportError:
    HAS_ICS = False

try:
    from draugr_cache import DraugrDB, get_db as _get_db, extract_system_id
    HAS_CACHE = True
except ImportError:
    HAS_CACHE = False
    _get_db = None
    extract_system_id = lambda f: Path(f).stem

try:
    from draugr_diff import compute_diff, build_diff_report, export_diff_csv, load_scan_csv
    HAS_DIFF = True
except ImportError:
    HAS_DIFF = False

try:
    from draugr_advisories import resolve_advisory, enrich_rows_with_advisories
    HAS_ADVISORIES = True
except ImportError:
    HAS_ADVISORIES = False

try:
    from draugr_poam import export_poam
    HAS_POAM = True
except ImportError:
    HAS_POAM = False

try:
    from draugr_fleet import build_fleet_report_from_db
    HAS_FLEET = True
except ImportError:
    HAS_FLEET = False
    def build_fleet_report_from_db(*a, **kw) -> str: return ""  # type: ignore

try:
    from draugr_alerts import check_alerts, dispatch_alerts, load_alert_config
    HAS_ALERTS = True
except ImportError:
    HAS_ALERTS = False
    def load_alert_config() -> dict: return {}                                          # type: ignore
    def check_alerts(*a, **kw) -> list: return []                                       # type: ignore
    def dispatch_alerts(*a, **kw) -> dict: return {"email": 0, "webhook": 0}            # type: ignore


# ----------------------------------------------------------------------
# Third‑party imports
# ----------------------------------------------------------------------
try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import (
        QAction, QColor, QDesktopServices, QFont, QLinearGradient,
        QPainter, QPainterPath, QPalette, QPixmap, QRadialGradient,
    )
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFrame,
        QHBoxLayout,
        QFileDialog,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QSplashScreen,
        QSizePolicy,
        QTextBrowser,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    HAS_PYQT6 = True
except ImportError:  # pragma: no cover
    HAS_PYQT6 = False

# ----------------------------------------------------------------------
# Constants – NVD / EPSS / KEV / Exploit sources
# ----------------------------------------------------------------------
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_API_KEY = "19f1852b-0f76-41af-99d2-61f6d8c2bd41"
OTX_API_KEY = "dd6ce4f928bbbe4c578d30a5696f124a5279621d2e7fb77f6dbbcc9b6ca886e9"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
VULNERS_API_URL = "https://vulners.com/api/v3/search/id/"
RATE_LIMIT_DELAY = 0.5
USER_AGENT = "nvd-cve-puller/2.0"
DRAUGR_VERSION = "2.0.2"
# GitHub repository for update checks — format: "owner/repo"
# Configurable via Settings → Update Settings. Stored in prefs.json.
_GITHUB_REPO: str = ""


def _load_github_repo() -> str:
    """Load the configured GitHub repo slug from prefs."""
    global _GITHUB_REPO
    try:
        from draugr_cache import _default_cache_dir
        import json as _j
        p = _default_cache_dir() / "prefs.json"
        if p.exists():
            prefs = _j.loads(p.read_text(encoding="utf-8"))
            _GITHUB_REPO = str(prefs.get("github_repo", "") or "")
    except Exception:
        pass
    return _GITHUB_REPO


def _save_github_repo(repo: str) -> None:
    """Persist the GitHub repo slug to prefs."""
    global _GITHUB_REPO
    _GITHUB_REPO = repo.strip()
    try:
        from draugr_cache import _default_cache_dir
        import json as _j
        p = _default_cache_dir() / "prefs.json"
        prefs: dict = {}
        if p.exists():
            try:
                prefs = _j.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
        prefs["github_repo"] = _GITHUB_REPO
        p.write_text(_j.dumps(prefs, indent=2), encoding="utf-8")
    except Exception:
        pass


def check_for_update() -> Optional[Dict[str, str]]:
    """
    Check GitHub releases API for a newer version of Draugr.
    Returns {"version": "x.y.z", "url": "..."} if an update is available, else None.
    Requires a GitHub repo configured via Settings → Update Settings.
    """
    repo = _GITHUB_REPO or _load_github_repo()
    if not repo or requests is None:
        return None
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        resp = requests.get(api_url, timeout=5, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 404:
            return None   # repo exists but has no releases yet
        if resp.status_code != 200:
            return None
        data   = resp.json()
        latest = str(data.get("tag_name", "") or "").lstrip("v")
        html_url = str(data.get("html_url", "") or "")
        if not latest:
            return None
        def _ver(s: str):
            try:
                return tuple(int(x) for x in s.split("."))
            except Exception:
                return (0,)
        if _ver(latest) > _ver(DRAUGR_VERSION):
            return {"version": latest, "url": html_url}
        return None
    except Exception:
        return None


# Default path for the CPE mapping override file (same directory as script)
CPE_MAPPING_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpe_mappings.json")

# Confidence threshold for CPE matching (0.0–1.0). Overridable via Settings.
_CPE_CONFIDENCE_THRESHOLD = 0.03


# ======================================================================
#  FEATURE 3 — Improved CPE Mapping with local overrides
# ======================================================================
def load_cpe_mappings(path: Optional[str] = None) -> Dict[str, str]:
    """
    Load the optional CPE mapping override file.

    Returns a dict of  { normalised_product_name : "vendor:product" }
    e.g.  { "apache tomcat": "apache:tomcat" }

    If the file doesn't exist or can't be parsed, returns {}.
    """
    path = path or CPE_MAPPING_DEFAULT
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            return {}
        # Normalise keys to lower‑case for matching
        return {str(k).lower().strip(): str(v).strip() for k, v in raw.items()}
    except Exception:
        return {}


def cpe_name_from_mapping(vendor_product: str, version: str = "*") -> str:
    """Build a full CPE 2.3 string from a 'vendor:product' pair and version."""
    vp = vendor_product.split(":", 1)
    vendor = vp[0] if vp else "*"
    product = vp[1] if len(vp) > 1 else "*"
    safe_ver = version if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{safe_ver}:*:*:*:*:*:*:*"


# ----------------------------------------------------------------------
# Low‑level HTTP helpers (single source of truth)
# ----------------------------------------------------------------------
def _safe_get_json(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """GET → JSON, raising on HTTP errors."""
    resp = requests.get(url, params=params, headers=headers or {}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _build_nvd_url(base: str, params: Dict[str, Any]) -> str:
    """
    Build an NVD request URL while preserving flag‑style parameters
    (noRejected, isVulnerable, keywordExactMatch) that must appear without "=True".
    """
    parts: List[str] = []
    for k, v in params.items():
        if v is None or v is False:
            continue
        if k in {"noRejected", "isVulnerable", "keywordExactMatch"}:
            if v:
                parts.append(k)          # bare flag
            continue
        parts.append(f"{quote_plus(str(k))}={quote_plus(str(v))}")
    return base + (("?" + "&".join(parts)) if parts else "")


def nvd_get_json(url: str, params: Dict[str, Any], timeout: int = 60, max_attempts: int = 4) -> Dict[str, Any]:
    """Robust wrapper around NVD API calls with retry, rate-limit handling, and response caching."""
    # ── Check cache first ─────────────────────────────────────────────
    if HAS_CACHE:
        try:
            db = _get_db()
            cached = db.get_nvd(url, params)
            if cached is not None:
                return cached
        except Exception:
            pass   # cache failure is non-fatal

    headers = {"User-Agent": USER_AGENT, "apiKey": NVD_API_KEY}
    request_url = _build_nvd_url(url, params)
    for attempt in range(1, max_attempts + 1):
        try:
            r = requests.get(request_url, headers=headers, timeout=timeout)
            if r.status_code in {429, 503}:
                retry_after = r.headers.get("Retry-After")
                sleep_s = (
                    float(retry_after)
                    if retry_after and retry_after.isdigit()
                    else min(2 * attempt, 10)
                )
                time.sleep(sleep_s)
                continue
            r.raise_for_status()
            data = r.json()

            # ── Store in cache ─────────────────────────────────────────
            if HAS_CACHE:
                try:
                    _get_db().put_nvd(url, params, data)
                except Exception:
                    pass

            return data
        except Exception as exc:
            if attempt == max_attempts:
                raise RuntimeError(
                    f"Failed NVD request for {url} with params={params!r}: {exc}"
                ) from exc
            time.sleep(min(2 * attempt, 10))
    raise RuntimeError("Unreachable code in nvd_get_json")


# ----------------------------------------------------------------------
# Product‑matching helpers (CPE‑based search)
# ----------------------------------------------------------------------
def normalize_text(value: str) -> str:
    """Lower‑case, strip, replace underscores, and collapse non‑alphanum."""
    value = value.lower().strip()
    value = value.replace("_", " ")
    value = re.sub(r"[^a-z0-9.+\- ]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value


def version_in_text(version: str, text: str) -> bool:
    """True if the normalized version string appears in the normalized text."""
    v = normalize_text(version)
    t = normalize_text(text)
    return bool(v and v in t)


def _strip_arch(name: str) -> str:
    """Remove architecture suffixes like (x64), (x86), (ARM64) for CPE matching."""
    return re.sub(r'\s*\((x64|x86|x86_64|arm64|arm|aarch64|win32|win64)\)', '', name, flags=re.IGNORECASE).strip()


def score_cpe_candidate(
    name: str,
    version: str,
    title: str,
    cpe_name: str,
    publisher: str = "",
) -> Tuple[int, float]:
    """
    Heuristic scoring of a CPE entry against the target product.

    Returns (raw_score, confidence_pct) where confidence_pct is 0.0–1.0.
    Higher confidence means the CPE is more likely to be the correct match.
    Publisher is used to narrow vendor matching when available.
    """
    score = 0
    name_clean = normalize_text(_strip_arch(name))
    t = normalize_text(title)
    c = normalize_text(cpe_name)

    # Token overlap
    for token in name_clean.split():
        if len(token) < 3:
            continue
        if token in t:
            score += 3
        if token in c:
            score += 3

    # Full name match
    if name_clean in t:
        score += 8
    if name_clean in c:
        score += 5

    # Version match (strongest signal)
    if version_in_text(version, title):
        score += 8
    if version_in_text(version, cpe_name):
        score += 12

    # Publisher / vendor match
    if publisher:
        pub_norm = normalize_text(publisher)
        pub_tokens = [t for t in pub_norm.split() if len(t) > 3]
        for pt in pub_tokens:
            if pt in c:
                score += 6
                break
        # Extract vendor field from CPE (cpe:2.3:a:vendor:product:...)
        cpe_parts = cpe_name.split(":")
        if len(cpe_parts) >= 5:
            cpe_vendor = cpe_parts[3].lower()
            for pt in pub_tokens:
                if pt in cpe_vendor or cpe_vendor in pt:
                    score += 8
                    break

    # Compute confidence as a fraction of the theoretical maximum
    max_possible = 3 * max(len(name_clean.split()), 1) + 8 + 5 + 12 + 8 + 14
    confidence = min(score / max_possible, 1.0)

    return score, confidence


def search_cpe_candidates(
    name: str,
    version: str,
    max_candidates: int = 5,
    cpe_mappings: Optional[Dict[str, str]] = None,
    publisher: str = "",
    min_confidence: float = 0.05,
) -> List[Dict[str, str]]:
    """
    Return the top-scoring CPE entries for name/version.

    If cpe_mappings contains an override for name, use it directly.
    Publisher is used to improve vendor matching accuracy.
    min_confidence filters out low-quality matches (0.0–1.0).
    Each returned entry includes a 'confidence' key (0.0–1.0).
    """
    # Architecture-stripped name for CPE matching
    name_clean = _strip_arch(name)

    # --- Check local override first ---
    if cpe_mappings:
        key = normalize_text(name_clean)
        vp  = cpe_mappings.get(key) or cpe_mappings.get(normalize_text(name))
        if vp:
            cpe = cpe_name_from_mapping(vp)
            return [{"cpeName": cpe, "title": f"{name} (local mapping)", "confidence": 1.0}]

    # --- Online NVD CPE search ---
    params = {"keywordSearch": name_clean, "resultsPerPage": 100}
    data   = nvd_get_json(NVD_CPE_URL, params)
    products = data.get("products", []) or []

    candidates: List[Tuple[int, float, Dict[str, str]]] = []
    for item in products:
        cpe      = item.get("cpe", {}) if isinstance(item, dict) else {}
        cpe_name = cpe.get("cpeName", "")
        title    = cpe.get("title", "")
        if not cpe_name:
            continue

        sc, conf = score_cpe_candidate(name_clean, version, title, cpe_name, publisher)
        if sc <= 0 or conf < min_confidence:
            continue
        candidates.append((sc, conf, {"cpeName": cpe_name, "title": title, "confidence": round(conf, 3)}))

    candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)

    seen: set = set()
    best: List[Dict[str, str]] = []
    for _, _, entry in candidates:
        cpe_name = entry["cpeName"]
        if cpe_name in seen:
            continue
        seen.add(cpe_name)
        best.append(entry)
        if len(best) >= max_candidates:
            break
    return best


def iter_cves_by_cpe(
    cpe_name: str,
    kev_index: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield CVE records for a single CPE string (paginated)."""
    start_index = 0
    page_size = 2000
    while True:
        params = {
            "cpeName": cpe_name,
            "isVulnerable": True,
            "noRejected": True,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        data = nvd_get_json(NVD_CVE_URL, params)
        cves = extract_cves(data, kev_index=kev_index)

        for cve in cves:
            yield cve

        total = int(data.get("totalResults", 0) or 0)
        returned = len(cves)
        start_index += returned
        if returned == 0 or start_index >= total:
            break


def iter_cves_by_keyword(
    name: str,
    version: str,
    kev_index: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Iterable[Dict[str, Any]]:
    """Fallback search using free‑text keyword‑search (also paginated)."""
    query = f"{name} {version}".strip()
    start_index = 0
    page_size = 2000
    while True:
        params = {
            "keywordSearch": query,
            "noRejected": True,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        data = nvd_get_json(NVD_CVE_URL, params)
        cves = extract_cves(data, kev_index=kev_index)

        for cve in cves:
            yield cve

        total = int(data.get("totalResults", 0) or 0)
        returned = len(cves)
        start_index += returned
        if returned == 0 or start_index >= total:
            break


# ----------------------------------------------------------------------
# CVE extraction & enrichment
# ----------------------------------------------------------------------
def _coerce_float(x: Any) -> Optional[float]:
    if x is None:
        return None
    try:
        return float(x)
    except Exception:
        return None


def pick_cvss(metrics: Dict[str, Any]) -> Tuple[
    Optional[str], Optional[float], Optional[str],
    Optional[float], Optional[float], Optional[str]
]:
    """Pick the best CVSS block (newest version preference)."""
    if not isinstance(metrics, dict):
        return (None, None, None, None, None, None)

    def first_block(key: str) -> Optional[Dict[str, Any]]:
        data = metrics.get(key)
        if isinstance(data, list) and data:
            return data[0]
        return None

    for version, key in [
        ("4.0", "cvssMetricV40"),
        ("3.1", "cvssMetricV31"),
        ("3.0", "cvssMetricV30"),
        ("2.0", "cvssMetricV2"),
    ]:
        block = first_block(key)
        if block and isinstance(block, dict):
            cvss_data = block.get("cvssData", {})
            base_score = _coerce_float(cvss_data.get("baseScore"))
            base_sev = cvss_data.get("baseSeverity")
            explo = _coerce_float(block.get("exploitabilityScore"))
            impact = _coerce_float(block.get("impactScore"))
            vector = cvss_data.get("vectorString")
            if any(v is not None for v in (base_score, base_sev, explo, impact, vector)):
                return (
                    version,
                    base_score,
                    str(base_sev) if base_sev is not None else None,
                    explo,
                    impact,
                    str(vector) if vector is not None else None,
                )
    return (None, None, None, None, None, None)


def _extract_cpe_matches(cve_obj: Dict[str, Any]) -> List[Dict[str, Optional[str]]]:
    """
    Pull vulnerable CPE match entries (with version range bounds)
    from a CVE's configurations node.
    """
    configs = cve_obj.get("configurations", [])
    cpe_matches: List[Dict[str, Optional[str]]] = []
    if not isinstance(configs, list):
        return cpe_matches
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    cpe_matches.append({
                        "criteria": match.get("criteria", ""),
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionStartExcluding": match.get("versionStartExcluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    })
    return cpe_matches


def _extract_reference_tags(cve_obj: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Inspect a CVE's references for exploit indicators.

    Returns (has_exploit_ref, exploit_urls) where:
      - has_exploit_ref is True if any reference is tagged "Exploit"
        or points to a known exploit host.
      - exploit_urls is the list of those reference URLs.
    """
    EXPLOIT_HOSTS = {
        "exploit-db.com",
        "packetstormsecurity.com",
        "github.com/advisories",
        "rapid7.com",
        "metasploit.com",
        "seclists.org",
    }
    refs = cve_obj.get("references", [])
    if not isinstance(refs, list):
        return False, []

    exploit_urls: List[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        tags = ref.get("tags", [])
        url = str(ref.get("url", "")).lower()

        is_exploit = False
        if isinstance(tags, list) and any(
            "exploit" in str(t).lower() for t in tags
        ):
            is_exploit = True
        if not is_exploit:
            for host in EXPLOIT_HOSTS:
                if host in url:
                    is_exploit = True
                    break
        if is_exploit:
            exploit_urls.append(ref.get("url", ""))

    return bool(exploit_urls), exploit_urls


def extract_cves(
    json_data: Dict[str, Any],
    kev_index: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Transform raw NVD JSON into a flat list of CVE dicts (with optional KEV data)."""
    vulns = json_data.get("vulnerabilities", [])
    out: List[Dict[str, Any]] = []
    if not isinstance(vulns, list):
        return out

    for v in vulns:
        cve_obj = v.get("cve", {}) if isinstance(v, dict) else {}
        if not isinstance(cve_obj, dict):
            continue

        cve_id = str(cve_obj.get("id") or "").strip().upper()

        # Pull English description
        descriptions = cve_obj.get("descriptions", [])
        description = ""
        if isinstance(descriptions, list):
            for d in descriptions:
                if isinstance(d, dict) and d.get("lang", "").lower() == "en":
                    description = str(d.get("value") or "").strip()
                    break

        metrics = cve_obj.get("metrics", {})
        cvss_version, base_score, base_sev, explo, impact, vector = pick_cvss(metrics)

        # CPE match data for version-range filtering
        cpe_matches = _extract_cpe_matches(cve_obj)

        # Exploit references from NVD
        has_exploit_ref, exploit_urls = _extract_reference_tags(cve_obj)

        # CWE (weakness) IDs — used for ATT&CK / D3FEND mapping
        cwe_ids: List[str] = []
        weaknesses = cve_obj.get("weaknesses", [])
        if isinstance(weaknesses, list):
            for w in weaknesses:
                for desc in w.get("description", []):
                    val = str(desc.get("value", "")).strip()
                    if val.startswith("CWE-") and val != "CWE-noinfo":
                        cwe_ids.append(val)

        kev_entry = (kev_index or {}).get(cve_id, {})
        if isinstance(kev_entry, dict):
            kev = kev_entry
        else:
            kev = {"kev_date_added": kev_entry or ""}

        out.append(
            {
                "cve_id": cve_id,
                "description": description,
                "published": str(cve_obj.get("published") or "")[:10],
                "cvss_version": cvss_version,
                "cvss_base_score": base_score,
                "cvss_severity": base_sev,
                "cvss_exploitability": explo,
                "cvss_impact": impact,
                "cvss_vector": vector,
                "cpe_matches": cpe_matches,
                "has_public_exploit": has_exploit_ref,
                "exploit_urls": exploit_urls,
                "cwe_ids": cwe_ids,
                "kev_known_exploited": kev.get("kev_known_exploited", "No"),
                "kev_date_added": kev.get("kev_date_added", ""),
                "kev_due_date": kev.get("kev_due_date", ""),
                "kev_vendor_project": kev.get("kev_vendor_project", ""),
                "kev_product": kev.get("kev_product", ""),
                "kev_ransomware_use": kev.get("kev_ransomware_use", ""),
                "kev_short_description": kev.get("kev_short_description", ""),
                "kev_required_action": kev.get("kev_required_action", ""),
            }
        )
    return out


def find_cves_for_software(
    name: str,
    version: str,
    max_per: int = 0,
    kev_index: Optional[Dict[str, Dict[str, Any]]] = None,
    cpe_mappings: Optional[Dict[str, str]] = None,
    publisher: str = "",
) -> List[Dict[str, Any]]:
    """
    High-level helper used by the UI and CLI.
    Returns a de-duplicated list of CVE dicts for name/version.
    1) CPE-based lookup (most precise — uses local mapping if available).
    2) Keyword fallback (covers imperfect CPE mappings).
    Publisher is passed to CPE scoring for vendor-aware matching.
    max_per limits total results (0 = no limit).
    """
    seen: set = set()
    results: List[Dict[str, Any]] = []

    for candidate in search_cpe_candidates(
        name, version,
        cpe_mappings=cpe_mappings,
        publisher=publisher,
    ):
        # Skip very low-confidence matches (below 3%) unless it's a local mapping
        conf = float(candidate.get("confidence", 1.0))
        if conf < _CPE_CONFIDENCE_THRESHOLD and "(local mapping)" not in candidate.get("title", ""):
            continue

        # ── Auto-learn high-confidence CPE matches ─────────────────────
        if HAS_CACHE and conf >= 0.35:
            try:
                cpe_str = candidate["cpeName"]
                parts   = cpe_str.split(":")
                if len(parts) >= 5:
                    vp = f"{parts[3]}:{parts[4]}"
                    _get_db().learn_cpe(name, vp, conf)
            except Exception:
                pass

        for cve in iter_cves_by_cpe(candidate["cpeName"], kev_index=kev_index):
            cve_id = cve["cve_id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            cve["cpe_confidence"] = conf
            results.append(cve)
            if 0 < max_per <= len(results):
                return results

    # Skip keyword fallback if we had a precise local mapping
    name_clean = _strip_arch(name)
    used_local = bool(
        cpe_mappings and (
            normalize_text(name_clean) in cpe_mappings or
            normalize_text(name) in cpe_mappings
        )
    )
    if not used_local:
        for cve in iter_cves_by_keyword(name, version, kev_index=kev_index):
            cve_id = cve["cve_id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            cve["cpe_confidence"] = 0.0   # keyword match — unscored
            results.append(cve)
            if 0 < max_per <= len(results):
                return results

    return results


# ----------------------------------------------------------------------
# Version‑range filtering
# ----------------------------------------------------------------------
def version_affected(scanned_version: str, cpe_matches: List[Dict[str, Optional[str]]]) -> Optional[bool]:
    """
    Check whether *scanned_version* falls within ANY vulnerable version
    range from the CVE's CPE match data.

    Returns:
        True  — at least one range confirms the version is affected.
        False — ranges exist and none of them include this version.
        None  — no usable range data; cannot determine (treat as unverified).
    """
    if not scanned_version:
        return None

    try:
        sv = Version(scanned_version)
    except InvalidVersion:
        return None

    has_any_range = False
    for match in (cpe_matches or []):
        start_inc = match.get("versionStartIncluding")
        start_exc = match.get("versionStartExcluding")
        end_inc   = match.get("versionEndIncluding")
        end_exc   = match.get("versionEndExcluding")

        if not any([start_inc, start_exc, end_inc, end_exc]):
            continue

        has_any_range = True
        in_range = True
        try:
            if start_inc and sv < Version(start_inc):
                in_range = False
            if start_exc and sv <= Version(start_exc):
                in_range = False
            if end_inc and sv > Version(end_inc):
                in_range = False
            if end_exc and sv >= Version(end_exc):
                in_range = False
        except InvalidVersion:
            continue

        if in_range:
            return True

    return False if has_any_range else None


# ======================================================================
#  Enrichment Pipeline — CWE lineage, CAPEC, ATT&CK, D3FEND, NIST 800-53
# ======================================================================
#
# When optional reference database files are present (cwe_db.json,
# capec_db.json, defend_db.json, nist_db.json), the scanner uses them
# for deep offline enrichment: CWE lineage expansion → CAPEC attack
# patterns → ATT&CK techniques → D3FEND countermeasures → NIST controls.
#
# When the DBs are absent, it falls back to the built-in CWE→ATT&CK
# lookup table and the live D3FEND API.
# ======================================================================

# Regex used by the CAPEC→ATT&CK extraction (from unified_cve_pipeline)
_TECH_REGEX = re.compile(r"NAME:ATTACK:ENTRY ID:([^:]+)")

# Default directory for reference DBs (same folder as the script)
_RESOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources")


def load_enrichment_dbs(
    resources_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Load optional enrichment reference databases.

    Returns a dict with keys 'cwe_db', 'capec_db', 'defend_db', 'nist_db'.
    Each value is the parsed JSON dict, or {} if the file is missing.
    """
    rdir = resources_dir or _RESOURCES_DIR
    dbs: Dict[str, Any] = {}
    for key, filename in [
        ("cwe_db",    "cwe_db.json"),
        ("capec_db",  "capec_db.json"),
        ("defend_db", "defend_db.json"),
        ("nist_db",   "nist_db.json"),
    ]:
        path = os.path.join(rdir, filename)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    dbs[key] = json.load(fh)
            except Exception:
                dbs[key] = {}
        else:
            # Also try .jsonl variant (defend_db.jsonl)
            alt = os.path.join(rdir, filename.replace(".json", ".jsonl"))
            if os.path.isfile(alt):
                try:
                    merged: Dict[str, Any] = {}
                    with open(alt, "r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if line:
                                obj = json.loads(line)
                                merged.update(obj)
                    dbs[key] = merged
                except Exception:
                    dbs[key] = {}
            else:
                dbs[key] = {}
    return dbs


# ------------------------------------------------------------------
# 1) CWE lineage expansion (BFS over CWE taxonomy)
# ------------------------------------------------------------------
def expand_cwe_lineage(cwe_ids: List[str], cwe_db: Dict[str, Any]) -> List[str]:
    """
    Walk the CWE taxonomy upward, returning all ancestor CWEs.
    Input/output use 'CWE-NNN' string format.
    """
    if not cwe_db:
        return cwe_ids

    # Convert to ints for DB lookup
    nums: set = set()
    for cwe in cwe_ids:
        try:
            nums.add(int(cwe.replace("CWE-", "")))
        except ValueError:
            continue

    visited = set(nums)
    queue = list(nums)
    while queue:
        cur = queue.pop(0)
        parents = cwe_db.get(str(cur), {}).get("parents", [])
        for p in parents:
            if p not in visited:
                visited.add(p)
                queue.append(p)

    return sorted(f"CWE-{n}" for n in visited)


# ------------------------------------------------------------------
# 2) CWE → CAPEC mapping
# ------------------------------------------------------------------
def map_cwe_to_capec(cwe_ids: List[str], cwe_db: Dict[str, Any]) -> List[str]:
    """Map CWE IDs to CAPEC attack pattern IDs using the CWE DB."""
    if not cwe_db:
        return []
    capecs: set = set()
    for cwe in cwe_ids:
        num = cwe.replace("CWE-", "")
        capecs.update(cwe_db.get(num, {}).get("capecs", []))
    return sorted(f"CAPEC-{c}" for c in capecs)


# ------------------------------------------------------------------
# 3) CAPEC → ATT&CK technique resolution
# ------------------------------------------------------------------
def resolve_techniques_from_capec(
    capec_ids: List[str],
    capec_db: Dict[str, Any],
) -> List[str]:
    """Extract ATT&CK technique IDs from CAPEC entries using regex."""
    if not capec_db:
        return []
    techs: set = set()
    for capec in capec_ids:
        num = capec.replace("CAPEC-", "")
        tech_str = capec_db.get(num, {}).get("techniques", "")
        if tech_str:
            techs.update(_TECH_REGEX.findall(tech_str))
    return sorted(techs)


# ------------------------------------------------------------------
# 4) Hardcoded CWE → ATT&CK fallback (used when DBs are absent)
# ------------------------------------------------------------------
CWE_TO_ATTACK: Dict[str, List[Tuple[str, str]]] = {
    # --- Injection / Code Execution ---
    "CWE-78":   [("T1059", "Command and Scripting Interpreter")],
    "CWE-77":   [("T1059", "Command and Scripting Interpreter")],
    "CWE-89":   [("T1190", "Exploit Public-Facing Application")],
    "CWE-94":   [("T1059", "Command and Scripting Interpreter"), ("T1203", "Exploitation for Client Execution")],
    "CWE-79":   [("T1189", "Drive-by Compromise"), ("T1059.007", "JavaScript")],
    "CWE-502":  [("T1203", "Exploitation for Client Execution"), ("T1059", "Command and Scripting Interpreter")],
    "CWE-917":  [("T1059", "Command and Scripting Interpreter")],
    "CWE-1321": [("T1059", "Command and Scripting Interpreter")],
    # --- Memory Corruption ---
    "CWE-119":  [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "CWE-120":  [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "CWE-125":  [("T1005", "Data from Local System")],
    "CWE-787":  [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "CWE-416":  [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "CWE-476":  [("T1499", "Endpoint Denial of Service")],
    "CWE-190":  [("T1203", "Exploitation for Client Execution")],
    "CWE-122":  [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    # --- Path / File ---
    "CWE-22":   [("T1083", "File and Directory Discovery"), ("T1005", "Data from Local System")],
    "CWE-434":  [("T1105", "Ingress Tool Transfer"), ("T1059", "Command and Scripting Interpreter")],
    "CWE-59":   [("T1083", "File and Directory Discovery")],
    # --- Authentication / Authorization ---
    "CWE-287":  [("T1078", "Valid Accounts"), ("T1190", "Exploit Public-Facing Application")],
    "CWE-306":  [("T1078", "Valid Accounts")],
    "CWE-862":  [("T1548", "Abuse Elevation Control Mechanism")],
    "CWE-863":  [("T1548", "Abuse Elevation Control Mechanism")],
    "CWE-269":  [("T1068", "Exploitation for Privilege Escalation")],
    "CWE-284":  [("T1548", "Abuse Elevation Control Mechanism")],
    "CWE-798":  [("T1078.001", "Default Accounts"), ("T1552", "Unsecured Credentials")],
    "CWE-521":  [("T1110", "Brute Force")],
    "CWE-307":  [("T1110", "Brute Force")],
    # --- Cryptographic ---
    "CWE-327":  [("T1557", "Adversary-in-the-Middle"), ("T1040", "Network Sniffing")],
    "CWE-295":  [("T1557", "Adversary-in-the-Middle")],
    "CWE-326":  [("T1557", "Adversary-in-the-Middle")],
    "CWE-330":  [("T1552", "Unsecured Credentials")],
    "CWE-319":  [("T1040", "Network Sniffing"), ("T1557", "Adversary-in-the-Middle")],
    # --- Information Disclosure ---
    "CWE-200":  [("T1005", "Data from Local System"), ("T1552", "Unsecured Credentials")],
    "CWE-209":  [("T1005", "Data from Local System")],
    "CWE-532":  [("T1552.004", "Private Keys"), ("T1005", "Data from Local System")],
    "CWE-611":  [("T1005", "Data from Local System"), ("T1190", "Exploit Public-Facing Application")],
    # --- Denial of Service ---
    "CWE-400":  [("T1499", "Endpoint Denial of Service")],
    "CWE-770":  [("T1499", "Endpoint Denial of Service")],
    "CWE-674":  [("T1499", "Endpoint Denial of Service")],
    # --- SSRF / Request Forgery ---
    "CWE-918":  [("T1090", "Proxy"), ("T1190", "Exploit Public-Facing Application")],
    "CWE-352":  [("T1189", "Drive-by Compromise")],
    # --- Misconfiguration / Logic ---
    "CWE-732":  [("T1222", "File and Directory Permissions Modification")],
    "CWE-276":  [("T1222", "File and Directory Permissions Modification")],
    "CWE-668":  [("T1005", "Data from Local System")],
    "CWE-362":  [("T1068", "Exploitation for Privilege Escalation")],
    "CWE-20":   [("T1190", "Exploit Public-Facing Application")],
    "CWE-116":  [("T1190", "Exploit Public-Facing Application")],
}


def map_cwe_to_attack(cwe_ids: List[str]) -> List[Dict[str, str]]:
    """
    Map CWE IDs to ATT&CK techniques using the hardcoded fallback table.
    Returns a de-duplicated list of {technique_id, technique_name} dicts.
    """
    seen: set = set()
    results: List[Dict[str, str]] = []
    for cwe in cwe_ids:
        for tid, tname in CWE_TO_ATTACK.get(cwe, []):
            if tid not in seen:
                seen.add(tid)
                results.append({"technique_id": tid, "technique_name": tname})
    return results


# ------------------------------------------------------------------
# 5) ATT&CK → D3FEND mapping (offline DB or live API)
# ------------------------------------------------------------------
def map_d3fend_offline(
    technique_ids: List[str],
    defend_db: Dict[str, Any],
) -> Dict[str, List[str]]:
    """
    Map ATT&CK technique IDs to D3FEND defenses using offline DB.
    Returns { technique_id: [defense_name, ...] }
    """
    if not defend_db:
        return {}
    mapping: Dict[str, List[str]] = {}
    for tid in technique_ids:
        defenses = defend_db.get(tid, {}).get("defenses", [])
        if defenses:
            mapping[tid] = defenses
    return mapping


def query_d3fend_for_technique(technique_id: str) -> List[Dict[str, str]]:
    """
    Query the MITRE D3FEND API for defensive countermeasures (online fallback).
    Returns a list of {d3fend_id, d3fend_name, d3fend_tactic} dicts.
    """
    url = f"https://d3fend.mitre.org/api/offensive-technique/attack/{technique_id}.json"
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []

    countermeasures: List[Dict[str, str]] = []
    bindings = (
        data.get("off_to_def", {})
            .get("results", {})
            .get("bindings", [])
    )
    seen: set = set()
    for b in bindings:
        def_tech = b.get("def_tech_label", {}).get("value", "")
        def_id   = b.get("def_tech", {}).get("value", "").rsplit("/", 1)[-1]
        tactic   = b.get("def_tactic_label", {}).get("value", "")
        if def_tech and def_id not in seen:
            seen.add(def_id)
            countermeasures.append({
                "d3fend_id": def_id,
                "d3fend_name": def_tech,
                "d3fend_tactic": tactic,
            })
    return countermeasures


def batch_d3fend_lookup(
    technique_ids: List[str],
    defend_db: Optional[Dict[str, Any]] = None,
) -> Dict[str, List[str]]:
    """
    For a list of ATT&CK technique IDs, return D3FEND countermeasures.
    Uses offline DB if available, otherwise falls back to live API.
    Returns { technique_id: [countermeasure_str, ...] }
    """
    # Try offline first
    if defend_db:
        result = map_d3fend_offline(technique_ids, defend_db)
        if result:
            return result

    # Online fallback
    mapping: Dict[str, List[str]] = {}
    for tid in technique_ids:
        cms = query_d3fend_for_technique(tid)
        if cms:
            mapping[tid] = [f"{c['d3fend_name']}" for c in cms]
    return mapping


# ------------------------------------------------------------------
# 6) ATT&CK → NIST 800-53 mapping (offline DB + built-in fallback)
# ------------------------------------------------------------------

# Built-in ATT&CK technique → NIST SP 800-53 Rev 5 control mapping.
# Covers every technique ID that CWE_TO_ATTACK can produce plus the
# most common additional techniques found in NVD data.
# Controls are listed most-specific first.
ATTACK_TO_NIST: Dict[str, List[str]] = {
    # --- Initial Access / Public-Facing Exploitation ---
    "T1190": ["SI-2 Flaw Remediation", "SI-10 Information Input Validation",
              "SC-7 Boundary Protection", "RA-5 Vulnerability Monitoring and Scanning",
              "SA-11 Developer Testing and Evaluation", "CM-7 Least Functionality"],
    "T1189": ["SC-7 Boundary Protection", "SI-3 Malicious Code Protection",
              "SI-4 System Monitoring", "CM-7 Least Functionality"],
    "T1133": ["AC-17 Remote Access", "IA-2 Identification and Authentication",
              "SC-7 Boundary Protection", "AC-3 Access Enforcement"],
    "T1078": ["IA-2 Identification and Authentication", "AC-2 Account Management",
              "AC-3 Access Enforcement", "AU-2 Event Logging",
              "IA-5 Authenticator Management"],
    "T1078.001": ["CM-6 Configuration Settings", "CM-7 Least Functionality",
                  "IA-5 Authenticator Management", "AC-2 Account Management"],
    # --- Execution ---
    "T1059": ["CM-7 Least Functionality", "SI-3 Malicious Code Protection",
              "AC-3 Access Enforcement", "AU-2 Event Logging",
              "SI-4 System Monitoring"],
    "T1059.007": ["CM-7 Least Functionality", "SI-10 Information Input Validation",
                  "SC-7 Boundary Protection", "SI-3 Malicious Code Protection"],
    "T1203": ["SI-2 Flaw Remediation", "SI-3 Malicious Code Protection",
              "CM-7 Least Functionality", "SC-7 Boundary Protection",
              "RA-5 Vulnerability Monitoring and Scanning"],
    "T1106": ["CM-7 Least Functionality", "AC-3 Access Enforcement",
              "SI-4 System Monitoring", "AU-2 Event Logging"],
    "T1053": ["AC-3 Access Enforcement", "CM-7 Least Functionality",
              "AU-2 Event Logging", "SI-4 System Monitoring"],
    # --- Persistence ---
    "T1547": ["CM-7 Least Functionality", "SI-4 System Monitoring",
              "AC-3 Access Enforcement", "AU-2 Event Logging"],
    "T1543": ["AC-3 Access Enforcement", "CM-7 Least Functionality",
              "AU-2 Event Logging", "SI-4 System Monitoring"],
    "T1574": ["CM-7 Least Functionality", "SI-7 Software Integrity",
              "AC-3 Access Enforcement", "AU-2 Event Logging"],
    # --- Privilege Escalation ---
    "T1068": ["SI-2 Flaw Remediation", "AC-6 Least Privilege",
              "CM-6 Configuration Settings", "RA-5 Vulnerability Monitoring and Scanning",
              "AU-2 Event Logging", "SI-4 System Monitoring"],
    "T1548": ["AC-6 Least Privilege", "AC-3 Access Enforcement",
              "CM-6 Configuration Settings", "AU-2 Event Logging",
              "SI-4 System Monitoring"],
    "T1134": ["AC-6 Least Privilege", "AC-3 Access Enforcement",
              "AU-2 Event Logging", "SI-4 System Monitoring"],
    # --- Defense Evasion ---
    "T1222": ["AC-3 Access Enforcement", "AC-6 Least Privilege",
              "AU-2 Event Logging", "SI-7 Software Integrity"],
    "T1562": ["AU-9 Protection of Audit Information", "AU-2 Event Logging",
              "CM-7 Least Functionality", "SI-4 System Monitoring"],
    "T1070": ["AU-9 Protection of Audit Information", "AU-2 Event Logging",
              "SI-7 Software Integrity"],
    "T1036": ["SI-3 Malicious Code Protection", "SI-7 Software Integrity",
              "AU-2 Event Logging"],
    # --- Credential Access ---
    "T1110": ["AC-7 Unsuccessful Login Attempts", "IA-2 Identification and Authentication",
              "IA-5 Authenticator Management", "AU-2 Event Logging",
              "SI-4 System Monitoring"],
    "T1552": ["IA-5 Authenticator Management", "SC-28 Protection of Information at Rest",
              "AC-3 Access Enforcement", "AU-2 Event Logging"],
    "T1552.004": ["SC-28 Protection of Information at Rest", "IA-5 Authenticator Management",
                  "AC-3 Access Enforcement"],
    "T1557": ["SC-8 Transmission Confidentiality and Integrity", "SC-7 Boundary Protection",
              "IA-3 Device Identification and Authentication", "SI-4 System Monitoring"],
    "T1040": ["SC-8 Transmission Confidentiality and Integrity",
              "SC-7 Boundary Protection", "SI-4 System Monitoring"],
    "T1003": ["AC-6 Least Privilege", "SC-28 Protection of Information at Rest",
              "IA-5 Authenticator Management", "AU-2 Event Logging"],
    # --- Discovery ---
    "T1083": ["AC-3 Access Enforcement", "AC-6 Least Privilege",
              "AU-2 Event Logging", "SI-4 System Monitoring"],
    "T1082": ["AC-3 Access Enforcement", "CM-8 System Component Inventory",
              "SI-4 System Monitoring", "AU-2 Event Logging"],
    "T1046": ["SC-7 Boundary Protection", "CM-7 Least Functionality",
              "SI-4 System Monitoring", "AU-2 Event Logging"],
    # --- Lateral Movement ---
    "T1021": ["AC-17 Remote Access", "AC-3 Access Enforcement",
              "IA-2 Identification and Authentication", "SC-7 Boundary Protection",
              "AU-2 Event Logging"],
    "T1210": ["SI-2 Flaw Remediation", "SC-7 Boundary Protection",
              "RA-5 Vulnerability Monitoring and Scanning", "CM-7 Least Functionality"],
    # --- Collection ---
    "T1005": ["AC-3 Access Enforcement", "AC-6 Least Privilege",
              "SC-28 Protection of Information at Rest", "AU-2 Event Logging",
              "SI-4 System Monitoring"],
    "T1213": ["AC-3 Access Enforcement", "AC-6 Least Privilege",
              "AU-2 Event Logging", "SI-4 System Monitoring"],
    # --- Exfiltration ---
    "T1041": ["SC-7 Boundary Protection", "SI-4 System Monitoring",
              "AU-2 Event Logging", "CA-7 Continuous Monitoring"],
    "T1048": ["SC-7 Boundary Protection", "SI-4 System Monitoring",
              "AU-2 Event Logging"],
    # --- Command and Control ---
    "T1090": ["SC-7 Boundary Protection", "SI-4 System Monitoring",
              "AU-2 Event Logging", "CA-7 Continuous Monitoring"],
    "T1071": ["SC-7 Boundary Protection", "SI-4 System Monitoring",
              "AU-2 Event Logging"],
    "T1105": ["SC-7 Boundary Protection", "SI-3 Malicious Code Protection",
              "SI-4 System Monitoring", "CM-7 Least Functionality"],
    # --- Impact ---
    "T1499": ["SC-5 Denial-of-Service Protection", "SI-4 System Monitoring",
              "SC-7 Boundary Protection", "IR-4 Incident Handling",
              "CA-7 Continuous Monitoring"],
    "T1485": ["CP-9 System Backup", "SI-7 Software Integrity",
              "AC-3 Access Enforcement", "AU-2 Event Logging"],
    "T1486": ["CP-9 System Backup", "SC-28 Protection of Information at Rest",
              "SI-3 Malicious Code Protection", "IR-4 Incident Handling"],
    "T1490": ["CP-9 System Backup", "AC-3 Access Enforcement",
              "SI-7 Software Integrity", "IR-4 Incident Handling"],
}


def map_nist_controls(
    technique_ids: List[str],
    nist_db: Dict[str, Any],
) -> List[str]:
    """
    Map ATT&CK technique IDs to NIST 800-53 controls.
    Uses the offline nist_db when available; falls back to the built-in
    ATTACK_TO_NIST table so controls are always populated.
    """
    controls: set = set()

    if nist_db:
        # Offline DB path
        for tid in technique_ids:
            controls.update(nist_db.get(tid, {}).get("nist_controls", []))

    if not controls:
        # Built-in fallback — also fills gaps for techniques not in the DB
        for tid in technique_ids:
            # Exact match first, then try parent technique (strip sub-technique suffix)
            matches = ATTACK_TO_NIST.get(tid, [])
            if not matches and "." in tid:
                parent = tid.split(".")[0]
                matches = ATTACK_TO_NIST.get(parent, [])
            controls.update(matches)

    return sorted(controls)


# ------------------------------------------------------------------
# 7) Unified enrichment runner (called per CVE)
# ------------------------------------------------------------------
def enrich_cve_frameworks(
    cwe_ids: List[str],
    enrichment_dbs: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run the full enrichment pipeline for a single CVE's CWE list.

    Returns a dict with keys:
        cwe_expanded  - list of CWE IDs (with lineage if DB available)
        capec_ids     - list of CAPEC IDs
        attack_techs  - list of {technique_id, technique_name} dicts
        technique_ids - flat list of technique ID strings
        d3fend        - list of countermeasure strings
        nist_controls - list of NIST 800-53 control strings
        used_pipeline - bool, True if offline DBs were used
    """
    cwe_db   = enrichment_dbs.get("cwe_db", {})
    capec_db = enrichment_dbs.get("capec_db", {})
    defend_db = enrichment_dbs.get("defend_db", {})
    nist_db  = enrichment_dbs.get("nist_db", {})

    has_dbs = bool(cwe_db or capec_db)

    # --- CWE lineage ---
    cwe_expanded = expand_cwe_lineage(cwe_ids, cwe_db) if cwe_db else list(cwe_ids)

    # --- ATT&CK techniques (two paths) ---
    technique_ids: List[str] = []
    attack_techs: List[Dict[str, str]] = []
    capec_ids: List[str] = []

    if has_dbs:
        # Pipeline path: CWE → CAPEC → ATT&CK
        capec_ids = map_cwe_to_capec(cwe_expanded, cwe_db)
        pipeline_tids = resolve_techniques_from_capec(capec_ids, capec_db)

        # Merge with hardcoded fallback for broader coverage
        fallback = map_cwe_to_attack(cwe_expanded)
        seen_tids: set = set(pipeline_tids)
        for t in fallback:
            if t["technique_id"] not in seen_tids:
                seen_tids.add(t["technique_id"])
                pipeline_tids.append(t["technique_id"])

        technique_ids = sorted(seen_tids)
        # Build the display list
        fallback_map = {t["technique_id"]: t["technique_name"] for t in fallback}
        attack_techs = [
            {"technique_id": tid, "technique_name": fallback_map.get(tid, tid)}
            for tid in technique_ids
        ]
    else:
        # Fallback-only path
        attack_techs = map_cwe_to_attack(cwe_ids)
        technique_ids = [t["technique_id"] for t in attack_techs]

    # --- D3FEND ---
    d3fend_map = batch_d3fend_lookup(technique_ids, defend_db)
    d3fend_flat: List[str] = []
    seen_d: set = set()
    for tid in technique_ids:
        for item in d3fend_map.get(tid, []):
            if item not in seen_d:
                seen_d.add(item)
                d3fend_flat.append(item)

    # --- NIST 800-53 ---
    nist_controls = map_nist_controls(technique_ids, nist_db)

    return {
        "cwe_expanded": cwe_expanded,
        "capec_ids": capec_ids,
        "attack_techs": attack_techs,
        "technique_ids": technique_ids,
        "d3fend": d3fend_flat,
        "nist_controls": nist_controls,
        "used_pipeline": has_dbs,
    }


# ======================================================================
#  FEATURE 2 — Exploit Intelligence (Vulners API batch lookup)
# ======================================================================
def query_exploits_vulners(cve_ids: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """
    Query the Vulners.com free search API for public exploit references.

    Returns: { cve_id: [ {source, title, url}, ... ] }
    Only CVEs that have at least one known exploit appear as keys.
    """
    if not cve_ids:
        return {}

    mapping: Dict[str, List[Dict[str, str]]] = {}
    batch_size = 50
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i: i + batch_size]
        try:
            resp = requests.post(
                VULNERS_API_URL,
                json={"id": batch},
                headers={"User-Agent": USER_AGENT},
                timeout=30,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            if data.get("result") != "OK":
                continue

            documents = data.get("data", {}).get("documents", {})
            for cve_id, refs in documents.items():
                if not isinstance(refs, list):
                    continue
                exploits = []
                for ref in refs:
                    ref_type = str(ref.get("type", "")).lower()
                    ref_family = str(ref.get("bulletinFamily", "")).lower()
                    if ref_type in ("exploit", "metasploit") or ref_family == "exploit":
                        exploits.append({
                            "source": ref.get("type", "unknown"),
                            "title": ref.get("title", ""),
                            "url": ref.get("href", ref.get("vhref", "")),
                        })
                if exploits:
                    mapping[cve_id.upper()] = exploits
        except Exception:
            continue
    return mapping


# ======================================================================
#  Threat Intelligence — CIRCL CVE Search + GreyNoise Community
#
#  Replaces the former AlienVault OTX integration which suffered from
#  persistent timeouts and reliability issues on the free tier.
#
#  Sources used (both free, no API key required):
#    • CIRCL CVE Search  — https://cve.circl.lu/api/
#      Per-CVE enrichment: references, vendor/product, CWE, CAPEC links.
#    • GreyNoise Community API — https://api.greynoise.io/v3/
#      Per-CVE exploitation activity: whether the CVE is being actively
#      exploited in the wild by IPs observed by GreyNoise sensors.
#
#  The public functions (query_otx_for_software / query_otx_for_cves /
#  _format_otx_intel) keep their original signatures so the rest of the
#  codebase requires no changes.
# ======================================================================

CIRCL_CVE_URL   = "https://cve.circl.lu/api/cve"
GREYNOISE_URL   = "https://api.greynoise.io/v3/community"


# ----------------------------------------------------------------------
# CIRCL helpers
# ----------------------------------------------------------------------

def _query_circl_cve(cve_id: str, timeout: int = 15) -> Dict[str, Any]:
    """Fetch enrichment data for a single CVE from CIRCL CVE Search."""
    try:
        resp = requests.get(
            f"{CIRCL_CVE_URL}/{cve_id}",
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json() or {}
    except Exception:
        pass
    return {}


def _query_greynoise_cve(cve_id: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Query the GreyNoise Community API for exploitation activity on a CVE.
    Returns a dict with keys: status, noise, riot, message, exploitation_stats.
    No API key needed for the community endpoint.
    """
    try:
        resp = requests.get(
            f"{GREYNOISE_URL}/{cve_id}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json() or {}
        if resp.status_code == 404:
            # 404 means GreyNoise has no data for this CVE — not an error
            return {"status": "no_data"}
    except Exception:
        pass
    return {"status": "error"}


# ----------------------------------------------------------------------
# Public API — same signatures as the former OTX functions
# ----------------------------------------------------------------------

def query_otx_for_software(
    name: str,
    version: str,
    api_key: str,          # kept for signature compatibility; unused
    max_pulses: int = 5,
) -> Dict[str, Any]:
    """
    Formerly queried AlienVault OTX for threat pulses.
    Now returns a lightweight stub — per-software intelligence is assembled
    from per-CVE CIRCL/GreyNoise data in query_otx_for_cves() instead.

    Returns the same dict shape the rest of the code expects:
        { pulse_count, pulses, error }
    """
    return {"pulse_count": 0, "pulses": [], "error": None}


def query_otx_for_cves(
    cve_ids: List[str],
    api_key: str,          # kept for signature compatibility; unused
) -> Dict[str, int]:
    """
    For each CVE ID, fetch threat intelligence from CIRCL and GreyNoise.

    Returns { cve_id: activity_score } where activity_score is a simple
    integer that approximates the former OTX "pulse count":
        • +1  if CIRCL has enrichment data (references, CAPEC, etc.)
        • +2  if GreyNoise reports active exploitation noise
        • +1  if GreyNoise reports RIOT (known benign scanner) context

    This keeps the table in the report populated with meaningful signal
    without requiring any API key.
    """
    if not cve_ids:
        return {}

    scores: Dict[str, int] = {}

    for cve_id in cve_ids:
        score = 0

        # --- CIRCL ---
        circl_data = _query_circl_cve(cve_id)
        if circl_data:
            # Any enrichment counts as at least 1
            score += 1
            # Extra weight if there are CAPEC attack patterns linked
            if circl_data.get("capec"):
                score += len(circl_data["capec"])

        # --- GreyNoise ---
        gn_data = _query_greynoise_cve(cve_id)
        if gn_data.get("noise"):
            score += 2   # actively scanned/exploited in the wild
        if gn_data.get("riot"):
            score += 1   # known scanner context

        # Populate cache with raw data so report formatters can read
        # GreyNoise/CIRCL signal (GreyNoise labels, CIRCL enrichment sections).
        # Previously the raw responses were discarded here and the cache was
        # never written, so those report sections always rendered empty.
        _THREAT_INTEL_CACHE[cve_id] = {
            "circl":     circl_data,
            "greynoise": gn_data,
        }

        if score > 0:
            scores[cve_id] = score

        time.sleep(0.2)   # be polite to free-tier endpoints

    return scores


# ----------------------------------------------------------------------
# Enrichment cache — declared in draugr_reports.py so both modules share
# the same dict object. Populated here during scan; read by report builders.
# ----------------------------------------------------------------------
try:
    from draugr_reports import _THREAT_INTEL_CACHE
except ImportError:
    _THREAT_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}  # type: ignore


def _get_cached_intel(cve_id: str) -> Dict[str, Any]:
    """Return combined CIRCL + GreyNoise data for a CVE, using cache."""
    if cve_id not in _THREAT_INTEL_CACHE:
        _THREAT_INTEL_CACHE[cve_id] = {
            "circl":      _query_circl_cve(cve_id),
            "greynoise":  _query_greynoise_cve(cve_id),
        }
    return _THREAT_INTEL_CACHE[cve_id]


def _format_otx_intel(
    software_name: str,
    software_version: str,
    otx_result: Dict[str, Any],      # stub from query_otx_for_software
    cve_pulse_counts: Dict[str, int], # scores from query_otx_for_cves
    top_cves: List[Dict[str, Any]],
) -> str:
    """
    Format threat intelligence (CIRCL + GreyNoise) into markdown for the
    executive report.  Formerly formatted AlienVault OTX pulse data.
    """
    lines: List[str] = ["## Threat Intelligence (CIRCL / GreyNoise)", ""]

    if not cve_pulse_counts:
        lines.append(
            f"- No external threat activity found for **{software_name} {software_version}** "
            "via CIRCL CVE Search or GreyNoise."
        )
        return "\n".join(lines)

    active_count = sum(1 for s in cve_pulse_counts.values() if s >= 3)
    lines.append(
        f"Threat intelligence enrichment found activity data for "
        f"**{len(cve_pulse_counts)}** CVE(s) in **{software_name} {software_version}**"
        + (f", of which **{active_count}** show active in-the-wild exploitation signals." if active_count else ".")
    )
    lines.append("")

    # --- CVE activity table ---
    lines.append("### CVE Threat Activity Summary")
    lines.append("| CVE ID | Activity Score | GreyNoise | Risk Score | CVSS Severity |")
    lines.append("|---|---|---|---|---|")
    cve_risk_map = {r.get("CVE ID", ""): r for r in top_cves}
    sorted_cves = sorted(cve_pulse_counts.items(), key=lambda x: x[1], reverse=True)

    for cve_id, score in sorted_cves[:10]:
        row  = cve_risk_map.get(cve_id, {})
        risk = row.get("Risk Score", "—")
        sev  = row.get("CVSS Severity", "—")

        # Pull GreyNoise signal from cache if available
        cached = _THREAT_INTEL_CACHE.get(cve_id, {})
        gn     = cached.get("greynoise", {})
        if gn.get("noise"):
            gn_label = "⚠ Active"
        elif gn.get("status") == "no_data":
            gn_label = "No data"
        elif gn.get("riot"):
            gn_label = "Known scanner"
        else:
            gn_label = "—"

        lines.append(f"| {cve_id} | {score} | {gn_label} | {risk} | {sev} |")

    lines.append("")

    # --- CIRCL enrichment highlights for top CVEs ---
    lines.append("### CVE Enrichment Details (CIRCL)")
    shown = 0
    for cve_id, _ in sorted_cves[:5]:
        cached = _THREAT_INTEL_CACHE.get(cve_id, {})
        circl  = cached.get("circl", {})
        if not circl:
            continue
        shown += 1
        lines.append(f"#### {cve_id}")
        if circl.get("summary"):
            lines.append(f"- **Summary:** {str(circl['summary'])[:300]}")
        vendors = [
            f"{p.get('vendor', '')} {p.get('product', '')}".strip()
            for p in (circl.get("vulnerable_product") or [])[:4]
        ]
        if vendors:
            lines.append(f"- **Affected Products:** {', '.join(vendors)}")
        capecs = circl.get("capec") or []
        if capecs:
            capec_str = ", ".join(
                f"CAPEC-{c.get('id', '')} ({c.get('name', '')})" for c in capecs[:3]
            )
            lines.append(f"- **Attack Patterns:** {capec_str}")
        refs = (circl.get("references") or [])[:3]
        for ref in refs:
            lines.append(f"- **Ref:** {ref}")
        gn = cached.get("greynoise", {})
        if gn.get("noise"):
            lines.append("- **GreyNoise:** ⚠ Active exploitation traffic observed in the wild")
        elif gn.get("message"):
            lines.append(f"- **GreyNoise:** {gn['message']}")
        lines.append("")

    if shown == 0:
        lines.append("- No additional CIRCL enrichment data available for top CVEs.")

    return "\n".join(lines).strip()


# ======================================================================
#  FEATURE 1 — Weighted Risk Score
# ======================================================================
def compute_risk_score(
    cve: Dict[str, Any],
    epss: Dict[str, str],
    version_confirmed: Optional[bool],
    has_public_exploit: bool,
    patch_age_days: Optional[int] = None,
) -> Tuple[float, str]:
    """
    Compute a weighted risk score (0–100) for a single CVE.

    Inputs & weights:
        CVSS base score (0–10)      → 35%  (normalised to 0–100)
        EPSS score (0–1)            → 25%  (normalised to 0–100)
        KEV listed                  → 20%  (binary: 0 or 100)
        Public exploit available    → 10%  (binary: 0 or 100)
        Version confirmed           → 10%  (confirmed=100, unverified=50, N/A=0)

    Patch age multiplier (applied after base score):
        ≥180 days unpatched         → ×1.15 (capped at 100)
        ≥90 days unpatched          → ×1.08
        ≥30 days unpatched          → ×1.03
        <30 days or unknown         → ×1.00 (no change)

    Returns (score_float, severity_label).
    """
    # --- CVSS component (35%) ---
    cvss_raw  = _coerce_float(cve.get("cvss_base_score")) or 0.0
    cvss_norm = (cvss_raw / 10.0) * 100.0

    # --- EPSS component (25%) ---
    epss_raw_str = epss.get("epss_score", "").replace("%", "")
    try:
        epss_pct = float(epss_raw_str)
    except (ValueError, TypeError):
        epss_pct = 0.0

    # --- KEV component (20%) ---
    kev_val = 100.0 if cve.get("kev_known_exploited") == "Yes" else 0.0

    # --- Public exploit component (10%) ---
    exploit_val = 100.0 if has_public_exploit else 0.0

    # --- Version confirmation component (10%) ---
    if version_confirmed is True:
        ver_val = 100.0
    elif version_confirmed is None:
        ver_val = 50.0
    else:
        ver_val = 0.0

    score = (
        cvss_norm     * 0.35
        + epss_pct    * 0.25
        + kev_val     * 0.20
        + exploit_val * 0.10
        + ver_val     * 0.10
    )

    # --- Patch age multiplier ---
    if patch_age_days is not None and patch_age_days > 0:
        if patch_age_days >= 180:
            score *= 1.15
        elif patch_age_days >= 90:
            score *= 1.08
        elif patch_age_days >= 30:
            score *= 1.03

    score = min(max(score, 0.0), 100.0)

    if score >= 80:
        label = "CRITICAL"
    elif score >= 60:
        label = "HIGH"
    elif score >= 40:
        label = "MEDIUM"
    elif score >= 20:
        label = "LOW"
    else:
        label = "INFO"

    return round(score, 1), label


# ----------------------------------------------------------------------
# EPSS & KEV helpers
# ----------------------------------------------------------------------
def query_epss(cve_ids: List[str]) -> Dict[str, Dict[str, str]]:
    """Query FIRST EPSS API in batches – returns mapping {cve → {score, percentile}}."""
    if not cve_ids:
        return {}
    mapping: Dict[str, Dict[str, str]] = {}
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        try:
            data = _safe_get_json(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
                timeout=30,
            )
            for entry in data.get("data", []):
                def fmt_pct(val):
                    try: return f"{float(val) * 100:.2f}%"
                    except (TypeError, ValueError): return ""
                mapping[entry.get("cve", "")] = {
                    "epss_score": fmt_pct(entry.get("epss", "")),
                    "epss_percentile": fmt_pct(entry.get("percentile", "")),
                }
        except Exception:  # pragma: no cover
            continue
    return mapping


def load_kev(path: str) -> Dict[str, Dict[str, str]]:
    """Load the CISA KEV JSON file."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return load_kev_from_data(data)
    except Exception:
        return {}


def load_kev_from_data(data: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """Parse KEV JSON data (already loaded) into the CVE → entry mapping."""
    mapping: Dict[str, Dict[str, str]] = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue
        mapping[cve_id] = {
            "kev_known_exploited": "Yes",
            "kev_date_added":        vuln.get("dateAdded", ""),
            "kev_due_date":          vuln.get("dueDate", ""),
            "kev_vendor_project":    vuln.get("vendorProject", ""),
            "kev_product":           vuln.get("product", ""),
            "kev_ransomware_use":    vuln.get("ransomwareUse", ""),
            "kev_short_description": vuln.get("shortDescription", ""),
            "kev_required_action":   vuln.get("requiredAction", ""),
        }
    return mapping


def fetch_kev_online(timeout: int = 30) -> Dict[str, Dict[str, str]]:
    """Fetch the CISA KEV catalog directly from the live feed URL."""
    data = _safe_get_json(KEV_FEED_URL, timeout=timeout)
    return load_kev_from_data(data)


def load_kev_with_fallback(path: str, *, log=None) -> Dict[str, Dict[str, str]]:
    """Try fetching KEV online first; fall back to local file."""
    def emit(msg, level="info"):
        if log:
            log(msg, level)

    try:
        emit("Fetching KEV catalog from CISA online feed …", "info")
        mapping = fetch_kev_online()
        emit(f"✔ Online KEV fetch succeeded — {len(mapping)} entries loaded.", "ok")
        return mapping
    except Exception as exc:
        emit(f"⚠ Online KEV fetch failed ({exc}); falling back to local file …", "warn")

    if path and os.path.isfile(path):
        mapping = load_kev(path)
        emit(f"✔ Local KEV file loaded — {len(mapping)} entries.", "ok")
        return mapping

    emit("⚠ No local KEV file available. KEV checks will be skipped.", "warn")
    return {}


def parse_software_list(path: str) -> List[Tuple[str, str, str, str]]:
    """
    Parse a software list file into (name, version, publisher, install_date) 4-tuples.

    Supported formats
    -----------------
    1. CSV with a header row containing a 'Name' column and optionally
       'Version', 'Publisher', and 'Install Date' columns. Any additional
       columns are ignored. Covers exports from Hapy, SCCM, PDQ, Qualys, etc:
           Name,Version,Publisher,Install Date
           Name,Version
    2. Two-column headerless CSV:  product,version
       (publisher and install_date will be empty strings)
    3. Plain text, one product name per line
       (version, publisher, and install_date will be empty strings)

    Lines starting with '#' are ignored in all formats.

    Install date normalisation
    --------------------------
    Dates in compact YYYYMMDD format (e.g. 20250417) are normalised to
    ISO 8601 (YYYY-MM-DD) for consistency with NVD/KEV date fields.
    """
    import csv as _csv

    entries: List[Tuple[str, str, str, str]] = []

    def _normalise_date(raw: str) -> str:
        """Convert YYYYMMDD → YYYY-MM-DD; pass through anything else."""
        s = raw.strip()
        if len(s) == 8 and s.isdigit():
            return f"{s[:4]}-{s[4:6]}-{s[6:]}"
        return s

    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        raw_content = f.read()

    lines = raw_content.splitlines()
    non_empty = [l for l in lines if l.strip() and not l.strip().startswith("#")]
    if not non_empty:
        return entries

    first = non_empty[0]
    is_csv = "," in first

    if is_csv:
        reader = _csv.DictReader(
            (l for l in lines if not l.strip().startswith("#")),
        )
        fieldnames_lower = [str(f).lower().strip() for f in (reader.fieldnames or [])]

        if "name" in fieldnames_lower:
            # Structured CSV with known headers — map by column name
            fn = reader.fieldnames or []

            def _col(keyword: str) -> Optional[str]:
                """Return the original fieldname whose lower-stripped form matches keyword."""
                return next((f for f in fn if f.strip().lower() == keyword), None)

            name_col    = _col("name")
            version_col = _col("version")
            pub_col     = next(
                (f for f in fn if f.strip().lower() in ("publisher", "vendor", "manufacturer")),
                None,
            )
            date_col    = next(
                (f for f in fn if "install" in f.strip().lower() or "date" in f.strip().lower()),
                None,
            )

            for row in reader:
                name    = str(row.get(name_col, "") or "").strip().strip('"')
                version = str(row.get(version_col, "") or "").strip().strip('"') if version_col else ""
                pub     = str(row.get(pub_col,  "") or "").strip().strip('"') if pub_col  else ""
                idate   = _normalise_date(str(row.get(date_col, "") or "")) if date_col else ""
                if name:
                    entries.append((name, version, pub, idate))
        else:
            # Headerless CSV — positional: col0=name, col1=version
            for row in reader:
                values  = list(row.values())
                name    = str(values[0] if values else "").strip().strip('"')
                version = str(values[1] if len(values) > 1 else "").strip().strip('"')
                if name and name.lower() != "name":
                    entries.append((name, version, "", ""))
    else:
        for line in non_empty:
            entries.append((line.strip(), "", "", ""))

    return entries


# ----------------------------------------------------------------------
# UI colour palette
# ----------------------------------------------------------------------
class C:
    # Palette derived from the Draugr splash image
    # Deep blood-dark backgrounds, crimson accents, warm grey text
    BG = "#170909"          # darkest background — near-black with red tint
    BG_CARD = "#1f0d0d"     # card surfaces — slightly lifted dark red-black
    BG_INPUT = "#290a0a"    # input fields — deep crimson-black
    BG_HOVER = "#3a1414"    # hover state — warm dark red
    BORDER = "#551e1e"      # borders — muted dark crimson
    FG = "#e4ccc8"          # primary text — warm off-white with red blush
    FG_DIM = "#7a5c5a"      # dimmed text — muted rose-grey
    FG_BRIGHT = "#f0dbd8"   # bright text — near white with warm tint
    ACCENT = "#cb322c"      # primary accent — strong Draugr crimson
    ACCENT_HOVER = "#d9645b"  # hover accent — lighter warm red
    GREEN = "#7a9e6e"       # success — desaturated olive green (fits dark palette)
    BLUE = "#7a8fa3"        # info — desaturated steel blue
    YELLOW = "#c4935a"      # warning — warm amber-orange
    RED = "#cb322c"         # error/critical — same as accent crimson
    ORANGE = "#d4722a"      # critical/exploit highlight — vivid burnt orange


# ----------------------------------------------------------------------
# Custom file‑picker row widget
# ----------------------------------------------------------------------
class FileRow(QWidget):
    """Label + line‑edit + Browse button."""

    INPUT_STYLE = f"""
        QLineEdit {{
            background: {C.BG_INPUT};
            color: {C.FG};
            border: 1px solid {C.BORDER};
            border-radius: 6px;
            padding: 8px 12px;
            font-family: 'Consolas', 'SF Mono', monospace;
            font-size: 12px;
            selection-background-color: {C.ACCENT};
        }}
        QLineEdit:focus {{
            border-color: {C.ACCENT};
        }}
    """

    BTN_STYLE = f"""
        QPushButton {{
            background: {C.BG_INPUT};
            color: {C.FG};
            border: 1px solid {C.BORDER};
            border-radius: 6px;
            padding: 8px 0;
            font-size: 12px;
        }}
        QPushButton:hover {{
            background: {C.BG_HOVER};
            border-color: {C.FG_DIM};
        }}
    """

    def __init__(self, label_text, placeholder="", is_file=False, file_filter="",pick_folder=False, parent=None):
        super().__init__(parent)
        self.is_save = is_file
        self.file_filter = file_filter
        self.pick_folder = pick_folder

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        label = QLabel(label_text)
        label.setFixedWidth(120)
        label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        label.setStyleSheet(f"color: {C.FG_DIM}; font-size: 12px;")
        layout.addWidget(label)

        self.input = QLineEdit()
        self.input.setPlaceholderText(placeholder)
        self.input.setStyleSheet(self.INPUT_STYLE)
        layout.addWidget(self.input, 1)
        if self.pick_folder or self.is_save:
            btn = QPushButton("Browse")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedWidth(80)
            btn.setStyleSheet(self.BTN_STYLE)
            btn.clicked.connect(self._browse)
            layout.addWidget(btn)

    def _browse(self):
        if self.pick_folder:
            path= QFileDialog.getExistingDirectory(
                self,
                "Select Folder",
                self.input.text() or os.getcwd(),
                QFileDialog.Option.ShowDirsOnly
            )
            self.input.setText(path)
        else:
            if self.is_save:
                path, _ = QFileDialog.getOpenFileName(self, "Select File", "", self.file_filter)
            else:
                path, _ = QFileDialog.getOpenFileName(self, "Open Software List", "", self.file_filter)
            if path:
                self.input.setText(path)

    def text(self) -> str:
        return self.input.text().strip()

    def setText(self, text: str):
        self.input.setText(text)

# ----------------------------------------------------------------------
# Helper – pluralise with count
# ----------------------------------------------------------------------
def _plural(count: int, singular: str, plural: str = "") -> str:
    """Return e.g. '3 CVEs' or '1 CVE'."""
    suffix = plural if plural else singular + "s"
    return f"{count} {suffix}" if count != 1 else f"{count} {singular}"


# ----------------------------------------------------------------------
# Executive Report helpers
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Report generation (draugr_reports.py)
# ----------------------------------------------------------------------
try:
    from draugr_reports import (
        build_executive_report_markdown,
        build_defensive_report,
        build_redteam_report,
    )
    HAS_REPORTS = True
except ImportError:
    HAS_REPORTS = False
    def build_executive_report_markdown(rows, report_title="", otx_results=None) -> str:  # type: ignore
        return "# Report generation unavailable\n\ndraugr_reports.py could not be imported.\n"
    def build_defensive_report(rows, report_title="") -> str:                             # type: ignore
        return "<html><body><p>draugr_reports.py could not be imported.</p></body></html>"
    def build_redteam_report(rows, report_title="", otx_results=None) -> str:             # type: ignore
        return "<html><body><p>draugr_reports.py could not be imported.</p></body></html>"


# ----------------------------------------------------------------------
# Worker thread – performs the heavy lifting
# ----------------------------------------------------------------------
class ScanWorker(QThread):
    log_signal = pyqtSignal(str, str)        # message, level
    progress_signal = pyqtSignal(int, int)   # current, total
    status_signal = pyqtSignal(str)          # status bar text
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str) 

    def __init__(self, software, kev_path, api_key, output_path, cpe_mapping_path="",
                 show_medium=True, show_low=True, resources_dir="", executive_report_path="", comp_report_path="",
                 error_log_path="", scan_log_path="", write_logs=True,
                 defensive_report_path="", redteam_report_path="", otx_api_key="",
                 input_file="", system_id="", software_tags: Optional[Dict[str, str]] = None):
        super().__init__()
        self.software = software
        self.kev_path = kev_path
        self.api_key = api_key
        self.output_path = output_path
        self.cpe_mapping_path = cpe_mapping_path
        self.show_medium = show_medium
        self.show_low = show_low
        self.resources_dir = resources_dir
        self.executive_report_path = executive_report_path
        self.comp_report_path = comp_report_path
        self.scan_log_path  = scan_log_path
        self.error_log_path = error_log_path
        self.write_logs = write_logs
        self.defensive_report_path = defensive_report_path
        self.redteam_report_path = redteam_report_path
        self.otx_api_key = otx_api_key
        self.input_file  = input_file
        self.system_id   = system_id or (extract_system_id(input_file) if input_file else "unknown")
        self.software_tags: Dict[str, str] = software_tags or {}
        self._scan_log_lines:  List[str] = []
        self._error_log_lines: List[str] = []
        self._skip_current: bool = False   # set True by GUI to skip the current software item

    def _emit_log(self, msg: str, level: str = "info"):
        """Emit to UI and buffer for scan log. Errors also go to the error buffer."""
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level.upper():7}] {msg}"
        self._scan_log_lines.append(line)
        if level == "error":
            self._error_log_lines.append(line)
            self.error_signal.emit(msg)
        self.log_signal.emit(msg, level)

    def _write_logs(self) -> None:
        """Write the accumulated log buffers to their files (only if write_logs is enabled)."""
        if not self.write_logs:
            return
        try:
            # Write the regular scan log
            with open(self.scan_log_path, "w", encoding="utf-8") as f:
                f.writelines(line + "\n" for line in self._scan_log_lines)

            # Write the error‑only log (only lines that were marked as errors)
            with open(self.error_log_path, "w", encoding="utf-8") as f:
                f.writelines(line + "\n" for line in self._error_log_lines)
        except Exception as exc:
            # If writing fails, emit a warning so the UI can show it
            self.log_signal.emit(f"Failed to write logs: {exc}", "error")

    def run(self):
        # --- API key status ---
        self._emit_log("── API Key Status ──────────────────────────────", "dim")
        if self.api_key and self.api_key != NVD_API_KEY:
            self._emit_log("✔ NVD API Key detected — using manually entered key", "ok")
        elif NVD_API_KEY:
            self._emit_log("✔ NVD API Key detected — using key from configuration", "ok")
        else:
            self._emit_log("⚠ NVD API Key not set — requests may be rate limited", "warn")
        self._emit_log("✔ Threat intelligence enabled — CIRCL CVE Search + GreyNoise Community (no key required)", "ok")
        self._emit_log("────────────────────────────────────────────────", "dim")

        # Load CPE mapping overrides
        self.status_signal.emit("Loading CPE mappings…")
        cpe_mappings = load_cpe_mappings(self.cpe_mapping_path or None)
        if cpe_mappings:
            self._emit_log(
                f"✔ CPE mapping file loaded — {len(cpe_mappings)} product overrides.", "ok",
            )
            self.status_signal.emit(f"CPE mappings loaded — {len(cpe_mappings)} overrides")
        else:
            self._emit_log(
                "ℹ No CPE mapping file found — using heuristic CPE search.", "dim",
            )

        # Load KEV index
        self.status_signal.emit("Loading KEV catalog…")
        kev_index = load_kev_with_fallback(self.kev_path or "", log=self._emit_log)
        kev_count = len(kev_index)
        if kev_count:
            self.status_signal.emit(f"KEV loaded — {kev_count} entries")

        # Load enrichment reference databases (CWE/CAPEC/D3FEND/NIST)
        self.status_signal.emit("Loading enrichment databases…")
        enrichment_dbs = load_enrichment_dbs(self.resources_dir or None)
        db_names = [k for k, v in enrichment_dbs.items() if v]
        if db_names:
            self._emit_log(
                f"✔ Enrichment DBs loaded: {', '.join(db_names)}", "ok",
            )
            self.status_signal.emit(f"Enrichment DBs loaded: {', '.join(db_names)}")
        else:
            self._emit_log(
                "ℹ No enrichment DBs found — using built-in mappings + D3FEND API.", "dim",
            )
        self._emit_log(
            "Highest Risk CVEs, CVEs with publicly available exploits, and Critical or High CVEs that match software and version will appear in log", "dim",
        )
        self._emit_log("All CVEs will appear in the output report.", "dim")

        all_rows: List[Dict[str, Any]] = []
        otx_intel_results: Dict[str, Any] = {}
        total = len(self.software)

        # ── Scan resume / cache setup ──────────────────────────────────
        db = None
        session_id = None
        if HAS_CACHE:
            try:
                db = _get_db()
                session_id = db.session_id_for(self.software)
                completed = db.completed_keys(session_id)
                resume_count = len(completed)
                if resume_count:
                    self._emit_log(
                        f"♻ Resume: {resume_count} software item(s) already cached "
                        f"from a previous session — skipping re-scan.", "ok"
                    )
                    # Pre-load cached rows
                    for (name, version, publisher, install_date) in self.software:
                        cached = db.get_cached_rows(session_id, name, version, publisher)
                        if cached:
                            all_rows.extend(cached)
            except Exception as e:
                self._emit_log(f"Cache unavailable: {e} — running without cache.", "warn")
                db = None

        for idx, (name, version, publisher, install_date) in enumerate(self.software, 1):

            if self.isInterruptionRequested():
                self._emit_log("Scan cancelled by user", "warning")
                self.status_signal.emit("Cancelled by user")
                break

            # ── Check resume cache ─────────────────────────────────────
            if db and session_id:
                cached = db.get_cached_rows(session_id, name, version, publisher)
                if cached is not None:
                    self._emit_log(f"[{idx}/{total}] ♻ {name} {version} — loaded from cache", "dim")
                    self.progress_signal.emit(idx, total)
                    continue   # rows already loaded above

            label = f"{name} {version}".strip()
            self._emit_log(f"[{idx}/{total}] Querying NVD for: {label}", "info")
            self.status_signal.emit(f"Scanning: {idx} of {total} — {label}")
            self.progress_signal.emit(idx - 1, total)  # show progress before work starts

            # -----------------------------------------------------------------
            # Retrieve CVEs
            # -----------------------------------------------------------------
            cves = find_cves_for_software(
                name, version,
                kev_index=kev_index,
                cpe_mappings=cpe_mappings,
                publisher=publisher,
            )
            if not cves:
                self._emit_log("✓ No CVEs found.", "ok")
                self.progress_signal.emit(idx, total)  # mark this item complete
                time.sleep(RATE_LIMIT_DELAY if not self.api_key else 0.6)
                continue

            self._emit_log(
                f"Found {_plural(len(cves), 'CVE')} — enriching with EPSS & exploit data…",
                "info",
            )

            cve_ids = [c["cve_id"] for c in cves]
            self.status_signal.emit(f"Scanning: {idx} of {total} — {label} — Enriching: EPSS")
            epss_map = query_epss(cve_ids)

            # --- Exploit intelligence (Vulners batch lookup) ---
            if self._skip_current:
                self._emit_log(f"⏭ Skipped: {label}", "warn")
                self._skip_current = False
                self.progress_signal.emit(idx, total)
                continue
            self.status_signal.emit(f"Scanning: {idx} of {total} — {label} — Enriching: Vulners")
            self._emit_log("Querying Vulners for public exploit data…", "dim")
            vulners_map = query_exploits_vulners(cve_ids)
            if vulners_map:
                self._emit_log(
                    f"✔ Vulners returned exploit data for {_plural(len(vulners_map), 'CVE')}.",
                    "ok",
                )

            # --- Threat intelligence: CIRCL CVE Search + GreyNoise Community ---
            self.status_signal.emit(f"Scanning: {idx} of {total} — {label} — Enriching: Threat Intel")
            self._emit_log("Querying CIRCL / GreyNoise for threat intelligence…", "dim")
            otx_result = query_otx_for_software(name, version, "")
            otx_cve_counts = query_otx_for_cves(cve_ids[:20], "")
            otx_result["cve_pulse_counts"] = otx_cve_counts
            otx_intel_results[f"{name} {version}".strip()] = otx_result
            active = sum(1 for s in otx_cve_counts.values() if s >= 3)
            if otx_cve_counts:
                self._emit_log(
                    f"✔ Threat intel: {len(otx_cve_counts)} CVE(s) enriched"
                    + (f", {active} with active exploitation signals" if active else "")
                    + f" for {label}",
                    "ok",
                )
            else:
                self._emit_log(f"Threat intel: no enrichment data found for {label}", "dim")

            # --- Framework enrichment handled per-CVE via enrich_cve_frameworks() ---

            # Severity counters
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            other_count = 0

            # Version‑verified CVE lists
            c_cves_confirmed: List[str] = []
            h_cves_confirmed: List[str] = []
            c_cves_unverified: List[str] = []
            h_cves_unverified: List[str] = []
            m_cves_confirmed: List[str] = []  # confirmed medium‑severity CVEs
            m_cves_unverified: List[str] = []  # unverified medium‑severity CVEs
            l_cves_confirmed: List[str] = []  # confirmed low‑severity CVEs
            l_cves_unverified: List[str] = []  # unverified low‑severity CVEs

            # Top‑risk CVEs for summary
            risk_entries: List[Tuple[float, str, str]] = []

            # Public exploit tracker for log output
            exploit_cves: List[Tuple[str, str]] = []  # (cid, sources_str)

            for cve in cves:
                cid   = cve["cve_id"]
                epss  = epss_map.get(cid, {})
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cid}"
                cvss_severity = str(cve.get("cvss_severity") or "").upper()

                # ---- version check ----
                affected = version_affected(version, cve.get("cpe_matches", []))

                # ---- exploit intelligence merge ----
                has_nvd_exploit = cve.get("has_public_exploit", False)
                vulners_exploits = vulners_map.get(cid, [])
                has_exploit = has_nvd_exploit or bool(vulners_exploits)

                exploit_sources: List[str] = []
                if has_nvd_exploit:
                    exploit_sources.append("NVD refs")
                if vulners_exploits:
                    sources = set(e.get("source", "") for e in vulners_exploits)
                    exploit_sources.extend(s for s in sources if s)

                # ---- false positive suppression ----
                if db and db.is_false_positive(cid, name):
                    self._emit_log(f"  ↷ {cid} suppressed (false positive list)", "dim")
                    continue

                # ---- skip current software item ----
                if self._skip_current:
                    break

                # ---- patch age for risk multiplier ----
                patch_age_int: Optional[int] = None
                if install_date:
                    try:
                        idate_obj = datetime.datetime.strptime(install_date, "%Y-%m-%d").date()
                        pub_raw   = str(cve.get("published", "") or "")[:10]
                        if pub_raw:
                            cve_date_obj = datetime.datetime.strptime(pub_raw, "%Y-%m-%d").date()
                            if idate_obj > cve_date_obj:
                                patch_age_int = (datetime.date.today() - idate_obj).days
                    except (ValueError, TypeError):
                        pass

                # ---- risk score ----
                risk_score, risk_label = compute_risk_score(
                    cve, epss, affected, has_exploit,
                    patch_age_days=patch_age_int,
                )

                # Use CVSS severity when available; fall back to risk label for unscored CVEs
                severity = cvss_severity if cvss_severity else risk_label.upper()

                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1
                elif severity == "MEDIUM":
                    medium_count += 1
                elif severity == "LOW":
                    low_count += 1
                else:
                    other_count += 1

                # ---- Framework enrichment (unified pipeline) ----
                cwe_ids = cve.get("cwe_ids", [])
                self.status_signal.emit(
                    f"Scanning: {idx} of {total} — {label} — Enriching: CVE Frameworks..."
                )
                fw = enrich_cve_frameworks(cwe_ids, enrichment_dbs)

                attack_str = "; ".join(
                    f"{t['technique_id']} ({t['technique_name']})" for t in fw["attack_techs"]
                )
                d3fend_str = "; ".join(fw["d3fend"])
                capec_str = "; ".join(fw["capec_ids"])
                nist_str = "; ".join(fw["nist_controls"])

                # ---- patch age calculation ----
                patch_age_days = ""
                if install_date:
                    try:
                        idate_obj2 = datetime.datetime.strptime(install_date, "%Y-%m-%d").date()
                        pub_raw2   = str(cve.get("published", "") or "")[:10]
                        if pub_raw2:
                            cve_date_obj2 = datetime.datetime.strptime(pub_raw2, "%Y-%m-%d").date()
                            if idate_obj2 >= cve_date_obj2:
                                patch_age_days = "0 (installed after CVE published)"
                            else:
                                delta2 = (datetime.date.today() - idate_obj2).days
                                patch_age_days = str(delta2)
                    except (ValueError, TypeError):
                        patch_age_days = ""

                # ---- vendor advisory ----
                advisory_url  = ""
                advisory_name = ""
                if HAS_ADVISORIES:
                    try:
                        adv = resolve_advisory(publisher, name, cid)
                        if adv:
                            advisory_url  = adv.get("url", "")
                            advisory_name = adv.get("name", "")
                    except Exception:
                        pass

                # ---- CPE match confidence ----
                cpe_conf = cve.get("cpe_confidence", "")
                if isinstance(cpe_conf, float) and cpe_conf > 0:
                    cpe_conf_str = f"{cpe_conf:.0%}"
                else:
                    cpe_conf_str = "keyword match"

                row_dict = {
                    "Software Name": name,
                    "Software Version": version,
                    "Publisher": publisher,
                    "Install Date": install_date,
                    "Patch Age (Days)": patch_age_days,
                    "CPE Match Confidence": cpe_conf_str,
                    "Vendor Advisory URL": advisory_url,
                    "Vendor Advisory Name": advisory_name,
                    "CVE ID": cid,
                    "Description": cve.get("description", ""),
                    "CVE Date": cve.get("published", ""),
                    "CVSS Version": cve.get("cvss_version", ""),
                    "CVSS Base Score": cve.get("cvss_base_score", ""),
                    "CVSS Severity": cve.get("cvss_severity", ""),
                    "CVSS Vector": cve.get("cvss_vector", ""),
                    "CVSS Exploitability": cve.get("cvss_exploitability", ""),
                    "CVSS Impact": cve.get("cvss_impact", ""),
                    "Known Exploited Vulnerability": cve.get("kev_known_exploited", "No"),
                    "KEV Date Added": cve.get("kev_date_added", ""),
                    "EPSS Score": epss.get("epss_score", ""),
                    "EPSS Percentile": epss.get("epss_percentile", ""),
                    "Public Exploit": "Yes" if has_exploit else "No",
                    "Exploit Sources": "; ".join(exploit_sources),
                    "Version Confirmed": (
                        "Yes" if affected is True
                        else "No" if affected is False
                        else "Unverified"
                    ),
                    "Risk Score": risk_score,
                    "Risk Level": risk_label,
                    "CWE": "; ".join(fw["cwe_expanded"]),
                    "CAPEC": capec_str,
                    "ATT&CK Techniques": attack_str,
                    "ATT&CK Tactics": "; ".join(
                        t["tactic"] for t in fw["attack_techs"] if t.get("tactic")
                    ),
                    "D3FEND Countermeasures": d3fend_str,
                    "NIST 800-53 Controls": nist_str,
                    "NVD URL": nvd_url,
                }

                # ── Apply software tags from the GUI tag manager ───────
                tag_val = (
                    self.software_tags.get(name.lower().strip()) or
                    self.software_tags.get(name.strip()) or ""
                )
                if tag_val:
                    row_dict["Tags"] = tag_val

                # ── ICS/OT ATT&CK enrichment ───────────────────────────
                if HAS_ICS:
                    row_dict = enrich_row_with_ics(row_dict)

                # ── Plugin enrichment and score modification ───────────
                if HAS_PLUGINS:
                    row_dict = apply_enrich_row(row_dict)
                    try:
                        modified_score = apply_score_modifier(row_dict, risk_score)
                        if modified_score != risk_score:
                            row_dict["Risk Score"] = round(modified_score, 1)
                    except Exception:
                        pass

                all_rows.append(row_dict)

                risk_entries.append((risk_score, risk_label, cid))

                # Track CVEs with public exploits — tag with risk_label, not CVSS severity
                if has_exploit:
                    exploit_cves.append((risk_score, cid, risk_label, "; ".join(exploit_sources)))

                # ----- version‑aware logging -----
                if severity in ("CRITICAL", "HIGH"):
                    if affected is True:
                        (c_cves_confirmed if severity == "CRITICAL" else h_cves_confirmed).append(cid)
                    elif affected is None:
                        (c_cves_unverified if severity == "CRITICAL" else h_cves_unverified).append(cid)
                elif severity == "MEDIUM" and self.show_medium:
                    if affected is True:
                        m_cves_confirmed.append(cid)
                    elif affected is None:
                        m_cves_unverified.append(cid)
                elif severity == "LOW" and self.show_low:
                    if affected is True:
                        l_cves_confirmed.append(cid)
                    elif affected is None:
                        l_cves_unverified.append(cid)

            # ----- Summary log lines -----
            def _log_cve_list(cve_list: List[str], level: str, tag: str = ""):
                suffix = f"  {tag}" if tag else ""
                for cid in cve_list:
                    self._emit_log(
                        f"•   \t{cid}: https://nvd.nist.gov/vuln/detail/{cid}{suffix}",
                        level,
                    )

            # 1) Top risk scores
            risk_entries.sort(key=lambda x: x[0], reverse=True)
            top = risk_entries[:5]
            if top and top[0][0] >= 40:
                self._emit_log("  ── Top risk CVEs (by weighted score) ──", "dim")
                for score, rlabel, cid in top:
                    color_level = {
                        "CRITICAL": "orange", "HIGH": "warn", "MEDIUM": "info",
                    }.get(rlabel, "dim")
                    self._emit_log(
                        f"    {score:5.1f}  [{rlabel}]  {cid}", color_level,
                    )

            # 2) Public exploits
            if exploit_cves:
                exploit_cves.sort(key=lambda x: x[0], reverse=True)
                self._emit_log(
                    f"  🔓 {_plural(len(exploit_cves), 'CVE')} with public exploits available",
                    "orange",
                )
                for erscore, ecid, erlabel, esources in exploit_cves:
                    self._emit_log(
                        f"•   \t{ecid}  [{erlabel}] - ({esources})",
                        "orange",
                    )

            # 3) Critical / High severity breakdown
            for sev_label, sev_count, confirmed_list, unverified_list, level in [
                ("CRITICAL", critical_count, c_cves_confirmed, c_cves_unverified, "orange"),
                ("HIGH",     high_count,     h_cves_confirmed, h_cves_unverified, "warn"),
            ]:
                if not sev_count:
                    continue
                confirmed = len(confirmed_list)
                unverified = len(unverified_list)
                filtered = sev_count - confirmed - unverified
                parts = []
                if confirmed:
                    parts.append(f"{confirmed} confirmed")
                if unverified:
                    parts.append(f"{unverified} unverified")
                if filtered:
                    parts.append(f"{filtered} not applicable to v{version}")
                detail = f" ({', '.join(parts)})" if parts else ""
                self._emit_log(
                    f"  ⚠ {_plural(sev_count, f'{sev_label} CVE')}{detail}",
                    level,
                )
                _log_cve_list(confirmed_list, level)
                _log_cve_list(unverified_list, level, tag="[unverified]")

            # 4) Medium / Low / Unranked (gated by user preference)
            if medium_count and self.show_medium:
                confirmed_m = len(m_cves_confirmed)
                unverified_m = len(m_cves_unverified)
                filtered_m = medium_count - confirmed_m - unverified_m
                parts_m = []
                if confirmed_m:
                    parts_m.append(f"{confirmed_m} confirmed")
                if unverified_m:
                    parts_m.append(f"{unverified_m} unverified")
                if filtered_m:
                    parts_m.append(f"{filtered_m} not applicable to v{version}")
                detail_m = f" ({', '.join(parts_m)})" if parts_m else ""
                self._emit_log(f" [!] {_plural(medium_count, 'MEDIUM CVE')}{detail_m}", "info")
                _log_cve_list(m_cves_confirmed, "info")
                _log_cve_list(m_cves_unverified, "info", tag="[unverified]")
            elif medium_count:
                self._emit_log(f" [!] {_plural(medium_count, 'MEDIUM CVE')} (hidden — enable in log filters)", "dim")

            if low_count and self.show_low:
                confirmed_l = len(l_cves_confirmed)
                unverified_l = len(l_cves_unverified)
                filtered_l = low_count - confirmed_l - unverified_l
                parts_l = []
                if confirmed_l:
                    parts_l.append(f"{confirmed_l} confirmed")
                if unverified_l:
                    parts_l.append(f"{unverified_l} unverified")
                if filtered_l:
                    parts_l.append(f"{filtered_l} not applicable to v{version}")
                detail_l = f" ({', '.join(parts_l)})" if parts_l else ""
                self._emit_log(f" [i] {_plural(low_count, 'LOW CVE')}{detail_l}", "info")
                _log_cve_list(l_cves_confirmed, "info")
                _log_cve_list(l_cves_unverified, "info", tag="[unverified]")
            elif low_count:
                self._emit_log(f" [i] {_plural(low_count, 'LOW CVE')} (hidden — enable in log filters)", "dim")

            if other_count:
                self._emit_log(f" [i] {_plural(other_count, 'UNRANKED CVE')}", "dim")

            # Respect NVD rate limits
            delay = 0.6 if self.api_key else RATE_LIMIT_DELAY
            self._emit_log(f"Rate‑limit pause ({delay}s) …", "dim")
            time.sleep(delay)

            # ── Save this item's rows to the scan cache ────────────────
            if db and session_id:
                try:
                    sw_rows_for_cache = [r for r in all_rows if r.get("Software Name") == name and r.get("Software Version") == version]
                    db.put_cached_rows(session_id, name, version, publisher, sw_rows_for_cache)
                except Exception:
                    pass

            if self._skip_current:
                self._emit_log(f"⏭ Skipped: {label} (skipped during CVE processing)", "warn")
                self._skip_current = False

            self.progress_signal.emit(idx, total)  # mark this item complete

        # Final progress — ensure bar shows 100%
        self.progress_signal.emit(total, total)

        # ── Plugin post-scan hook ──────────────────────────────────────
        if HAS_PLUGINS:
            try:
                all_rows = apply_on_scan_complete(all_rows)
            except Exception as e:
                self._emit_log(f"⚠ Plugin on_scan_complete failed: {e}", "warn")

        # Make rows accessible to the GUI results browser
        self._completed_rows = all_rows

        # -----------------------------------------------------------------
        # Write CSV — sorted by Risk Score descending
        # -----------------------------------------------------------------
        all_rows.sort(key=lambda r: r.get("Risk Score", 0), reverse=True)

        fieldnames = [
            "Software Name",
            "Software Version",
            "Publisher",
            "Install Date",
            "Patch Age (Days)",
            "CPE Match Confidence",
            "Vendor Advisory URL",
            "Vendor Advisory Name",
            "CVE ID",
            "Description",
            "Risk Score",
            "Risk Level",
            "CVE Date",
            "CVSS Version",
            "CVSS Base Score",
            "CVSS Severity",
            "CVSS Vector",
            "CVSS Exploitability",
            "CVSS Impact",
            "Known Exploited Vulnerability",
            "KEV Date Added",
            "EPSS Score",
            "EPSS Percentile",
            "Public Exploit",
            "Exploit Sources",
            "Version Confirmed",
            "CWE",
            "CAPEC",
            "ATT&CK Techniques",
            "ATT&CK Tactics",
            "D3FEND Countermeasures",
            "NIST 800-53 Controls",
            "ICS ATT&CK Techniques",
            "Tags",
            "NVD URL",
        ]
        self.status_signal.emit("Writing CSV…")
        try:
            with open(self.output_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(all_rows)
            self._emit_log(
                f"✅ Done — {len(all_rows)} CVEs written to: {self.output_path}",
                "ok",
            )
            if self.executive_report_path:
                self.status_signal.emit("Writing Reports…")
                exec_report_md = build_executive_report_markdown(
                    all_rows,
                    report_title="Executive Threat Intelligence Report",
                    otx_results=otx_intel_results,
                )
                with open(self.executive_report_path, "w", encoding="utf-8") as mdfile:
                    mdfile.write(exec_report_md)
                
                # Technical Security Assessment Report (replaces old comp_report)
                tech_report_path = self.comp_report_path or self.defensive_report_path
                if tech_report_path:
                    tech_html = build_defensive_report(
                        all_rows,
                        report_title="Technical Security Assessment Report",
                    )
                    with open(tech_report_path, "w", encoding="utf-8") as f:
                        f.write(tech_html)

                if self.redteam_report_path:
                    redteam_html = build_redteam_report(
                        all_rows,
                        report_title="Red Team Target Report",
                        otx_results=otx_intel_results,
                    )
                    with open(self.redteam_report_path, "w", encoding="utf-8") as f:
                        f.write(redteam_html)

                # ── POA&M XLSX export ──────────────────────────────────
                if HAS_POAM and tech_report_path:
                    try:
                        poam_path = str(tech_report_path).replace(
                            "_technical_report.html", "_poam.xlsx"
                        ).replace(
                            "_defensive_report.html", "_poam.xlsx"
                        )
                        n_poam = export_poam(
                            all_rows,
                            poam_path,
                            system_name=str(Path(self.output_path).stem),
                        )
                        self._emit_log(
                            f"✅ POA&M Export   → {poam_path} ({n_poam} entries)", "ok"
                        )
                    except Exception as e:
                        self._emit_log(f"⚠ POA&M export failed: {e}", "warn")

                # ── SBOM export ────────────────────────────────────────
                if HAS_SBOM and tech_report_path:
                    try:
                        sbom_path = str(tech_report_path).replace(
                            "_technical_report.html", "_sbom.json"
                        ).replace(
                            "_defensive_report.html", "_sbom.json"
                        )
                        n_comp = export_sbom(
                            all_rows,
                            sbom_path,
                            system_name=self.system_id or str(Path(self.output_path).stem),
                            tool_version=DRAUGR_VERSION,
                        )
                        self._emit_log(
                            f"📦 SBOM Export     → {sbom_path} ({n_comp} components)", "ok"
                        )
                    except Exception as e:
                        self._emit_log(f"⚠ SBOM export failed: {e}", "warn")
                if db and session_id:
                    try:
                        db.clear_session(session_id)
                    except Exception:
                        pass

                # ── Save to scan history (trend tracking) ─────────────
                if db and all_rows:
                    try:
                        is_new_system = len(db.get_scan_history(self.system_id, limit=1)) == 0
                        db.save_scan(
                            system_id=self.system_id,
                            input_file=self.input_file or self.output_path,
                            rows=all_rows,
                            system_label=self.system_id,
                        )
                        self._emit_log(
                            f"📈 Scan history saved for system: {self.system_id}", "ok"
                        )
                    except Exception as e:
                        self._emit_log(f"⚠ Trend save failed: {e}", "warn")
                        is_new_system = False

                    # ── Check and dispatch alerts ──────────────────────
                    if HAS_ALERTS:
                        try:
                            alert_cfg  = load_alert_config()
                            alerts     = check_alerts(
                                all_rows, self.system_id,
                                is_new_system=is_new_system,
                                cfg=alert_cfg,
                            )
                            if alerts:
                                sent = dispatch_alerts(alerts, alert_cfg)
                                self._emit_log(
                                    f"🔔 {len(alerts)} alert(s) dispatched "
                                    f"(email:{sent['email']}, webhook:{sent['webhook']})", "ok"
                                )
                        except Exception as e:
                            self._emit_log(f"⚠ Alert dispatch failed: {e}", "warn")

                    # ── Fleet report ───────────────────────────────────
                    if HAS_FLEET and tech_report_path:
                        try:
                            fleet_path = str(tech_report_path).replace(
                                "_technical_report.html", "_fleet_report.html"
                            ).replace(
                                "_defensive_report.html", "_fleet_report.html"
                            )
                            fleet_html = build_fleet_report_from_db(db)
                            with open(fleet_path, "w", encoding="utf-8") as f:
                                f.write(fleet_html)
                            self._emit_log(f"🌐 Fleet Report    → {fleet_path}", "ok")
                        except Exception as e:
                            self._emit_log(f"⚠ Fleet report failed: {e}", "warn")

                written = [
                    f"✅ Executive Report → {self.executive_report_path}",
                    f"✅ Technical Report → {self.comp_report_path}",
                ]
                if self.defensive_report_path:
                    written.append(f"✅ Defensive Report → {self.defensive_report_path}")
                if self.redteam_report_path:
                    written.append(f"✅ Red Team Report  → {self.redteam_report_path}")
                self._emit_log("\n".join(written), "ok")

            if self.executive_report_path:
                report_names = " + ".join(filter(None, [
                    os.path.basename(self.output_path),
                    os.path.basename(self.executive_report_path),
                    os.path.basename(self.comp_report_path),
                    os.path.basename(self.defensive_report_path) if self.defensive_report_path else "",
                    os.path.basename(self.redteam_report_path) if self.redteam_report_path else "",
                ]))
                self.status_signal.emit(
                    f"Complete — {len(all_rows)} CVEs across {total} products → {report_names}"
                )
            else:
                self.status_signal.emit(
                    f"Complete — {len(all_rows)} CVEs across {total} products → {os.path.basename(self.output_path)}"
                )
        except Exception as exc:  # pragma: no cover
            self._emit_log(f"❌ Failed to write CSV: {exc}", "error")
            self.status_signal.emit(f"Error — Failed to write CSV: {exc}")
        finally:
            self._write_logs()
            self.finished_signal.emit()


# ----------------------------------------------------------------------
# Main window
# ----------------------------------------------------------------------
class CVEScannerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Draugr — Threat Intelligence System  v{DRAUGR_VERSION}")
        self.setMinimumSize(960, 780)
        self.resize(1060, 860)
        self.scanning    = False
        self.worker      = None
        self.logging     = False
        self._scan_rows: List[Dict[str, Any]] = []   # last scan results for browser
        self._profiles:  Dict[str, Dict[str, Any]] = self._load_profiles()
        self._tags:      Dict[str, str] = self._load_tags()
        _load_github_repo()   # pre-load repo slug from prefs
        self._build_ui()
        # Async version check
        if HAS_CACHE:
            try:
                from PyQt6.QtCore import QTimer as _QTimer
                _QTimer.singleShot(3000, self._check_version)
            except Exception:
                pass

    def _load_profiles(self) -> Dict[str, Dict[str, Any]]:
        from draugr_cache import _default_cache_dir
        path = _default_cache_dir() / "scan_profiles.json"
        try:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_profiles(self) -> None:
        try:
            from draugr_cache import _default_cache_dir
            path = _default_cache_dir() / "scan_profiles.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._profiles, f, indent=2)
        except Exception:
            pass

    def _load_tags(self) -> Dict[str, str]:
        try:
            from draugr_cache import _default_cache_dir
            path = _default_cache_dir() / "software_tags.json"
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_tags(self) -> None:
        try:
            from draugr_cache import _default_cache_dir
            path = _default_cache_dir() / "software_tags.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._tags, f, indent=2)
        except Exception:
            pass

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        central.setStyleSheet(f"background: {C.BG};")

        root = QVBoxLayout(central)
        root.setContentsMargins(28, 20, 28, 20)
        root.setSpacing(0)

        header = QLabel("DRAUGR")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            f"color: {C.ACCENT}; font-size: 64px; font-weight: 700; letter-spacing: 4px;"
        )
        root.addWidget(header)

        subtitle = QLabel("THREAT    INTELLIGENCE    SYSTEM") #  ·  
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(
            f"color: {C.FG_DIM}; font-size: 12px; letter-spacing: 3px; padding-bottom: 16px;"
        )
        root.addWidget(subtitle)

        # Configuration card
        card = QFrame()
        card.setStyleSheet(
            f"""
            QFrame {{
                background: {C.BG_CARD};
                border: 1px solid {C.BORDER};
                border-radius: 12px;
            }}
            """
        )
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 20, 24, 20)
        card_layout.setSpacing(10)

        section = QLabel("CONFIGURATION")
        section.setStyleSheet(
            f"color: {C.ACCENT}; font-size: 11px; font-weight: 600; letter-spacing: 2px; border: none;"
        )
        card_layout.addWidget(section)

        self.sw_row = FileRow(
            "Software List ", "Path to file …",
            is_file=True,file_filter="CSV and Text files (*.csv *.txt);;All files (*)",
        )
        card_layout.addWidget(self.sw_row)

        self.out_row = FileRow(
            "Output Directory ", "Enter folder name …",
            file_filter="",
        )
        card_layout.addWidget(self.out_row)

        # --- Optional fields (hidden by default, toggled via Settings menu) ---
        self.kev_row = FileRow(
            "KEV JSON ", "Optional — json file for KEV check",
            is_file=True,file_filter="JSON files (*.json);;All files (*)",
        )
        self.kev_row.setVisible(False)
        card_layout.addWidget(self.kev_row)

        self.cpe_row = FileRow(
            "CPE Mappings ", "Optional — cpe_mappings.json",
            is_file=True,file_filter="JSON files (*.json);;All files (*)",
        )
        if os.path.isfile(CPE_MAPPING_DEFAULT):
            self.cpe_row.setText(CPE_MAPPING_DEFAULT)
        self.cpe_row.setVisible(False)
        card_layout.addWidget(self.cpe_row)

        self.resources_row = FileRow(
            "Resources Dir ", "Optional — folder with cwe_db.json, capec_db.json, etc.",
            file_filter="", pick_folder=True
        )
        if os.path.isdir(_RESOURCES_DIR):
            self.resources_row.setText(_RESOURCES_DIR)
        self.resources_row.setVisible(False)
        card_layout.addWidget(self.resources_row)

        # API key entry (hidden by default)
        self.api_widget = QWidget()
        api_layout = QHBoxLayout(self.api_widget)
        api_layout.setContentsMargins(0, 0, 0, 0)
        api_layout.setSpacing(8)

        api_label = QLabel("NVD API Key ")
        api_label.setFixedWidth(120)
        api_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        api_label.setStyleSheet(f"color: {C.FG_DIM}; font-size: 12px; border: none;")
        api_layout.addWidget(api_label)

        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("Optional — will use instead of default key")
        self.api_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_input.setStyleSheet(FileRow.INPUT_STYLE)
        api_layout.addWidget(self.api_input, 1)

        self.api_widget.setVisible(False)
        card_layout.addWidget(self.api_widget)

        # OTX API key entry (hidden by default)
        self.otx_widget = QWidget()
        otx_layout = QHBoxLayout(self.otx_widget)
        otx_layout.setContentsMargins(0, 0, 0, 0)
        otx_layout.setSpacing(8)

        otx_label = QLabel("OTX API Key ")
        otx_label.setFixedWidth(120)
        otx_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        otx_label.setStyleSheet(f"color: {C.FG_DIM}; font-size: 12px; border: none;")
        otx_layout.addWidget(otx_label)

        self.otx_input = QLineEdit()
        self.otx_input.setPlaceholderText("Optional — AlienVault OTX API key for threat intelligence")
        self.otx_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.otx_input.setStyleSheet(FileRow.INPUT_STYLE)
        if OTX_API_KEY:
            self.otx_input.setText(OTX_API_KEY)
        otx_layout.addWidget(self.otx_input, 1)

        self.otx_widget.setVisible(False)
        card_layout.addWidget(self.otx_widget)

        root.addWidget(card)

        # ---- Menu bar (Settings) ----
        self._build_menu_bar()

        # Buttons
        root.addSpacing(14)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(0)

        ACTION_BTN_STYLE = f"""
        QPushButton {{
            background: {C.RED};
            color: {C.BG};
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        QPushButton:hover {{
            background: {C.ACCENT_HOVER};
        }}
        QPushButton:disabled {{
            background: {C.BORDER};
            color: {C.FG_DIM};
        }}
        """

        self.scan_btn = QPushButton("▶   Start Scan")
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.setFixedSize(200, 44)
        self.scan_btn.setStyleSheet(ACTION_BTN_STYLE)

        self.stop_btn = QPushButton("■   Stop Scan")
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setFixedSize(200, 44)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(ACTION_BTN_STYLE)

        self.skip_btn = QPushButton("⏭   Skip Current")
        self.skip_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.skip_btn.setFixedSize(160, 44)
        self.skip_btn.setEnabled(False)
        self.skip_btn.setToolTip("Skip the software item currently being scanned and move to the next one")
        self.skip_btn.setStyleSheet(ACTION_BTN_STYLE.replace(C.RED, C.ORANGE))

        self.diff_btn = QPushButton("Δ   Compare Scans")
        self.diff_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.diff_btn.setFixedSize(160, 44)
        self.diff_btn.setToolTip("Compare two Draugr output CSVs and generate a delta report")
        self.diff_btn.setStyleSheet(ACTION_BTN_STYLE.replace(C.RED, C.BLUE))

        self.trend_btn = QPushButton("📈  Scan History")
        self.trend_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.trend_btn.setFixedSize(150, 44)
        self.trend_btn.setToolTip("View scan history and trends across all systems")
        self.trend_btn.setStyleSheet(ACTION_BTN_STYLE.replace(C.RED, "#2a7a2a"))

        btn_row.addWidget(self.scan_btn)
        btn_row.addSpacing(5)
        btn_row.addWidget(self.stop_btn)
        btn_row.addSpacing(5)
        btn_row.addWidget(self.skip_btn)
        btn_row.addSpacing(14)
        btn_row.addWidget(self.diff_btn)
        btn_row.addSpacing(5)
        btn_row.addWidget(self.trend_btn)
        self.scan_btn.clicked.connect(lambda: self._start_scan(generate_executive_report=True))
        self.stop_btn.clicked.connect(self._stop_scan)
        self.skip_btn.clicked.connect(self._skip_current_software)
        self.diff_btn.clicked.connect(self._run_diff)
        self.trend_btn.clicked.connect(self._view_scan_history)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # Progress
        root.addSpacing(14)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet(
            f"""
            QProgressBar {{
                background: {C.BG_CARD};
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background: {C.GREEN};
                border-radius: 3px;
            }}
            """
        )
        self.progress_bar.setValue(0)
        root.addWidget(self.progress_bar)

        self.progress_label = QLabel("")
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_label.setStyleSheet(f"color: {C.FG_DIM}; font-size: 11px;")
        root.addWidget(self.progress_label)

        # Log filter checkboxes
        root.addSpacing(8)
        filter_row = QHBoxLayout()
        filter_row.setSpacing(16)

        CHECKBOX_STYLE = f"""
        QCheckBox {{
            color: {C.FG_DIM};
            font-size: 12px;
            spacing: 6px;
        }}
        QCheckBox::indicator {{
            width: 14px;
            height: 14px;
            border: 1px solid {C.BORDER};
            border-radius: 3px;
            background: {C.BG_INPUT};
        }}
        QCheckBox::indicator:checked {{
            background: {C.ACCENT};
            border-color: {C.ACCENT};
        }}
        QCheckBox::indicator:hover {{
            border-color: {C.FG_DIM};
        }}
        """

        log_label = QLabel("LOG")
        log_label.setStyleSheet(
            f"color: {C.FG_DIM}; font-size: 10px; font-weight: 600; letter-spacing: 2px;"
        )
        filter_row.addWidget(log_label)
        filter_row.addStretch()

        self.chk_medium = QCheckBox("Show MEDIUM")
        self.chk_medium.setChecked(True)
        self.chk_medium.setStyleSheet(CHECKBOX_STYLE)
        filter_row.addWidget(self.chk_medium)

        self.chk_low = QCheckBox("Show LOW")
        self.chk_low.setChecked(False)
        self.chk_low.setStyleSheet(CHECKBOX_STYLE)
        filter_row.addWidget(self.chk_low)

        root.addLayout(filter_row)
        root.addSpacing(4)

        self.chk_medium.stateChanged.connect(self._update_show_medium)
        self.chk_low.stateChanged.connect(self._update_show_low)

        # ── Tab widget: Scan Log | Results Browser ─────────────────────
        from PyQt6.QtWidgets import QTabWidget, QSplitter, QTableWidget, QTableWidgetItem

        TAB_STYLE = f"""
        QTabWidget::pane {{
            border: 1px solid {C.BORDER};
            background: {C.BG_CARD};
            border-radius: 0 6px 6px 6px;
        }}
        QTabBar::tab {{
            background: {C.BG};
            color: {C.FG_DIM};
            border: 1px solid {C.BORDER};
            border-bottom: none;
            padding: 5px 14px;
            margin-right: 2px;
            border-radius: 4px 4px 0 0;
            font-size: 11px;
        }}
        QTabBar::tab:selected {{
            background: {C.BG_CARD};
            color: {C.FG};
        }}
        QTabBar::tab:hover {{
            background: {C.BG_HOVER};
        }}
        """
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet(TAB_STYLE)

        # Tab 1: Scan log
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet(
            f"""
            QTextEdit {{
                background: {C.BG_CARD};
                color: {C.FG};
                border: none;
                padding: 12px;
                font-family: 'Consolas', 'SF Mono', 'Menlo', monospace;
                font-size: 12px;
                selection-background-color: {C.ACCENT};
            }}
            """
        )
        self.tab_widget.addTab(self.log, "📋  Scan Log")

        # Tab 2: Results browser (table + CVE detail panel)
        results_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: filterable results table
        results_left = QWidget()
        results_left_layout = QVBoxLayout(results_left)
        results_left_layout.setContentsMargins(6, 6, 0, 6)
        results_left_layout.setSpacing(4)

        # Source bar — shows what is loaded + Load CSV button
        source_bar = QHBoxLayout()
        self._results_source_label = QLabel("No results loaded")
        self._results_source_label.setStyleSheet(
            f"color:{C.FG_DIM}; font-size:10px; font-style:italic;"
        )
        load_csv_btn = QPushButton("📂  Load CSV")
        load_csv_btn.setFixedHeight(28)
        load_csv_btn.setToolTip("Load a previously saved Draugr scan CSV into the Results Browser")
        load_csv_btn.setStyleSheet(
            f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; border-radius:4px; "
            f"padding:2px 10px; font-size:11px; }}"
            f"QPushButton:hover {{ background:{C.BG_HOVER}; }}"
        )
        load_csv_btn.clicked.connect(self._load_csv_into_browser)
        source_bar.addWidget(self._results_source_label, 1)
        source_bar.addWidget(load_csv_btn)
        results_left_layout.addLayout(source_bar)

        # Filter bar
        filter_bar = QHBoxLayout()
        self._results_filter = QLineEdit()
        self._results_filter.setPlaceholderText("Filter by CVE, software, severity…")
        self._results_filter.setStyleSheet(
            f"QLineEdit {{ background:{C.BG_INPUT}; color:{C.FG}; border:1px solid {C.BORDER}; "
            f"border-radius:4px; padding:4px 8px; font-size:11px; }}"
        )
        self._results_filter.textChanged.connect(self._apply_results_filter)

        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._sev_filter.setStyleSheet(
            f"QComboBox {{ background:{C.BG_INPUT}; color:{C.FG}; border:1px solid {C.BORDER}; "
            f"border-radius:4px; padding:4px 6px; font-size:11px; min-width:90px; }}"
        )
        self._sev_filter.currentTextChanged.connect(self._apply_results_filter)

        self._kev_filter = QCheckBox("KEV only")
        self._kev_filter.setStyleSheet(CHECKBOX_STYLE)
        self._kev_filter.stateChanged.connect(self._apply_results_filter)

        filter_bar.addWidget(self._results_filter, 1)
        filter_bar.addWidget(self._sev_filter)
        filter_bar.addWidget(self._kev_filter)
        results_left_layout.addLayout(filter_bar)

        RESULTS_TABLE_COLS = ["CVE ID", "Software", "Severity", "Risk", "CVSS", "KEV", "Exploit", "EPSS"]
        self._results_table = QTableWidget(0, len(RESULTS_TABLE_COLS))
        self._results_table.setHorizontalHeaderLabels(RESULTS_TABLE_COLS)
        self._results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._results_table.setAlternatingRowColors(True)
        self._results_table.setSortingEnabled(True)
        self._results_table.horizontalHeader().setStretchLastSection(True)
        self._results_table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_CARD}; color:{C.FG}; "
            f"border:none; gridline-color:{C.BORDER}; alternate-background-color:{C.BG}; }}"
            f"QHeaderView::section {{ background:{C.BG_INPUT}; color:{C.FG_DIM}; "
            f"border:1px solid {C.BORDER}; padding:5px; font-weight:600; font-size:11px; }}"
            f"QTableWidget::item:selected {{ background:{C.ACCENT}; color:#fff; }}"
        )
        self._results_table.currentItemChanged.connect(
            lambda current, _prev: self._on_result_row_selected(
                self._results_table.row(current) if current else -1
            )
        )
        results_left_layout.addWidget(self._results_table)
        results_splitter.addWidget(results_left)

        # Right: CVE detail panel
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 6, 6, 6)
        detail_layout.setSpacing(0)

        detail_header = QLabel("CVE Detail")
        detail_header.setStyleSheet(
            f"color:{C.FG_DIM}; font-size:10px; font-weight:600; "
            f"letter-spacing:2px; padding:0 0 4px 8px;"
        )
        detail_layout.addWidget(detail_header)

        self._detail_panel = QTextBrowser()
        self._detail_panel.setReadOnly(True)
        self._detail_panel.setStyleSheet(
            f"QTextBrowser {{ background:{C.BG}; color:{C.FG}; border:1px solid {C.BORDER}; "
            f"border-radius:6px; padding:10px; font-size:12px; }}"
        )
        self._detail_panel.setPlaceholderText("Select a CVE from the table to see details…")
        self._detail_panel.setOpenExternalLinks(True)
        detail_layout.addWidget(self._detail_panel)
        results_splitter.addWidget(detail_widget)
        results_splitter.setSizes([520, 380])
        results_splitter.setStyleSheet(
            f"QSplitter::handle {{ background:{C.BORDER}; width:2px; }}"
        )

        self.tab_widget.addTab(results_splitter, "🔍  Results Browser")
        root.addWidget(self.tab_widget, 1)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {C.FG_DIM};
                background: {C.BG_CARD};
                border: 1px solid {C.BORDER};
                border-radius: 6px;
                padding: 6px 12px;
                font-family: 'Consolas', 'SF Mono', 'Menlo', monospace;
                font-size: 11px;
            }}
            """
        )
        root.addSpacing(4)
        root.addWidget(self.status_label)
    
    # Slot that runs whenever the Medium checkbox changes
    def _update_show_medium(self):
        self.show_medium = self.chk_medium.isChecked()
        # if a worker is already running, push the change to it
        if self.worker is not None:
            self.worker.show_medium = self.show_medium

    # Slot that runs whenever the Low checkbox changes
    def _update_show_low(self):
        self.show_low = self.chk_low.isChecked()
        if self.worker is not None:
            self.worker.show_low = self.show_low

    # --------------------------------------------------------------
    # Menu bar
    # --------------------------------------------------------------
    def _build_menu_bar(self):
        menu_bar = self.menuBar()
        menu_bar.setStyleSheet(
            f"""
            QMenuBar {{
                background: {C.BG};
                color: {C.FG_DIM};
                border: none;
                font-size: 12px;
            }}
            QMenuBar::item {{
                padding: 6px 14px;
                border-radius: 4px;
            }}
            QMenuBar::item:selected {{
                background: {C.BG_HOVER};
                color: {C.FG};
            }}
            QMenu {{
                background: {C.BG_CARD};
                color: {C.FG};
                border: 1px solid {C.BORDER};
                border-radius: 6px;
                padding: 4px 0;
                font-size: 12px;
            }}
            QMenu::item {{
                padding: 6px 24px;
            }}
            QMenu::item:selected {{
                background: {C.BG_HOVER};
            }}
            QMenu::separator {{
                height: 1px;
                background: {C.BORDER};
                margin: 4px 8px;
            }}
            QMenu::indicator {{
                width: 14px;
                height: 14px;
                margin-left: 6px;
            }}
            QMenu::indicator:checked {{
                background: {C.ACCENT};
                border: 1px solid {C.ACCENT};
                border-radius: 3px;
            }}
            QMenu::indicator:unchecked {{
                background: {C.BG_INPUT};
                border: 1px solid {C.BORDER};
                border-radius: 3px;
            }}
            """
        )

        settings_menu = menu_bar.addMenu("Settings")

        # --- Optional input toggles ---
        self._act_kev = QAction("KEV JSON File", self)
        self._act_kev.setCheckable(True)
        self._act_kev.setChecked(False)
        self._act_kev.toggled.connect(lambda on: self.kev_row.setVisible(on))
        settings_menu.addAction(self._act_kev)

        self._act_cpe = QAction("CPE Mappings File", self)
        self._act_cpe.setCheckable(True)
        self._act_cpe.setChecked(False)
        self._act_cpe.toggled.connect(lambda on: self.cpe_row.setVisible(on))
        settings_menu.addAction(self._act_cpe)

        self._act_api = QAction("NVD API Key", self)
        self._act_api.setCheckable(True)
        self._act_api.setChecked(False)
        self._act_api.toggled.connect(lambda on: self.api_widget.setVisible(on))
        settings_menu.addAction(self._act_api)

        self._act_otx = QAction("OTX API Key", self)
        self._act_otx.setCheckable(True)
        self._act_otx.setChecked(False)
        self._act_otx.toggled.connect(lambda on: self.otx_widget.setVisible(on))
        settings_menu.addAction(self._act_otx)

        settings_menu.addSeparator()

        self._act_resources = QAction("Enrichment DBs Folder", self)
        self._act_resources.setCheckable(True)
        self._act_resources.setChecked(False)
        self._act_resources.toggled.connect(lambda on: self.resources_row.setVisible(on))
        settings_menu.addAction(self._act_resources)

        settings_menu.addSeparator()

        self._act_write_logs = QAction("Write Logs to File", self)
        self._act_write_logs.setCheckable(True)
        self._act_write_logs.setChecked(True)
        settings_menu.addAction(self._act_write_logs)

        settings_menu.addSeparator()

        act_fp = QAction("False Positive Suppression…", self)
        act_fp.setToolTip("Manage CVE false positive suppression list")
        act_fp.triggered.connect(self._manage_false_positives)
        settings_menu.addAction(act_fp)

        act_alerts = QAction("Alert Configuration…", self)
        act_alerts.setToolTip("Configure email and webhook alerting")
        act_alerts.triggered.connect(self._configure_alerts)
        settings_menu.addAction(act_alerts)

        settings_menu.addSeparator()

        act_theme = QAction("Theme…", self)
        act_theme.setToolTip("Switch between Dark and Light themes")
        act_theme.triggered.connect(self._change_theme)
        settings_menu.addAction(act_theme)

        act_conf = QAction("CPE Confidence Threshold…", self)
        act_conf.setToolTip("Adjust minimum CPE match confidence to reduce false positives")
        act_conf.triggered.connect(self._set_confidence_threshold)
        settings_menu.addAction(act_conf)

        act_cpe_ed = QAction("CPE Mappings Editor…", self)
        act_cpe_ed.setToolTip("Review and edit auto-learned and manual CPE mappings")
        act_cpe_ed.triggered.connect(self._edit_cpe_mappings)
        settings_menu.addAction(act_cpe_ed)

        settings_menu.addSeparator()

        act_profiles = QAction("Scan Profiles…", self)
        act_profiles.setToolTip("Save and load named scan configurations")
        act_profiles.triggered.connect(self._manage_profiles)
        settings_menu.addAction(act_profiles)

        act_pdf = QAction("Export PDF Reports…", self)
        act_pdf.setToolTip("Export the last scan reports as PDF files")
        act_pdf.triggered.connect(self._export_pdf)
        settings_menu.addAction(act_pdf)

        act_plugins = QAction("Plugins Manager…", self)
        act_plugins.setToolTip("View loaded plugins and open the plugins directory")
        act_plugins.triggered.connect(self._manage_plugins)
        settings_menu.addAction(act_plugins)

        act_kev_check = QAction("Check KEV for Latest Scan…", self)
        act_kev_check.setToolTip("Re-check the last scan's CVEs against the live CISA KEV feed")
        act_kev_check.triggered.connect(self._check_kev_now)
        settings_menu.addAction(act_kev_check)

        act_tags = QAction("Manage Software Tags…", self)
        act_tags.setToolTip("Assign tags to software items (e.g. internet-facing, critical) to influence risk scoring")
        act_tags.triggered.connect(self._manage_tags)
        settings_menu.addAction(act_tags)

        settings_menu.addSeparator()

        act_update_settings = QAction("Update Settings…", self)
        act_update_settings.setToolTip("Configure your GitHub repository for update checking")
        act_update_settings.triggered.connect(self._update_settings)
        settings_menu.addAction(act_update_settings)

        act_check_update = QAction(f"Check for Updates  (v{DRAUGR_VERSION})", self)
        act_check_update.setToolTip("Check your GitHub repository for a newer release of Draugr")
        act_check_update.triggered.connect(self._check_for_update_manual)
        settings_menu.addAction(act_check_update)

    # --------------------------------------------------------------
    # Helper slots
    # --------------------------------------------------------------
    def _append_log(self, msg: str, level: str = "info"):
        colors = {
            "ok": C.GREEN,
            "warn": C.YELLOW,
            "error": C.RED,
            "info": C.BLUE,
            "dim": C.FG_DIM,
            "orange": C.ORANGE,
        }
        color = colors.get(level, C.FG)
        safe_msg = html.escape(msg).replace("\n", "<br>")
        self.log.append(f'<span style="color:{color}">{safe_msg}</span>')

    def _update_progress(self, current: int, total: int):
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(current)
        pct = int((current / total) * 100) if total else 0
        self.progress_label.setText(f"{current} / {total}   ({pct}%) Complete")

    def _update_status(self, text: str):
        self.status_label.setText(text)

    def _scan_finished(self):
        self._append_log("Scan Finished.", "info")
        self.scanning = False
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.skip_btn.setEnabled(False)
        self.scan_btn.setText("▶   Start Scan")
        try:
            self.worker._write_logs()
        except Exception:
            pass
        # Populate results browser — guard against cancelled/errored scans
        completed_rows = getattr(self.worker, '_completed_rows', None)
        if completed_rows:
            self._scan_rows = completed_rows
            self._populate_results_table(self._scan_rows)
            import datetime as _dt
            self._results_source_label.setText(
                f"Live scan — {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')} "
                f"— {len(self._scan_rows)} finding(s)"
            )
            self.tab_widget.setCurrentIndex(1)
        self.worker = None

    def _start_scan(self, generate_executive_report: bool = False):
        if self.scanning:
            return

        sw_path = self.sw_row.text()
        if not sw_path or not os.path.isfile(sw_path):
            QMessageBox.critical(self, "Error", "Please select a valid software list file.")
            return
        out_path = self.out_row.text()
        if not out_path:
            QMessageBox.critical(self, "Error", "Please specify an output path.")
            return
        base_dir = Path("results")
        user_dir = Path(self.out_row.text())
        output_dir = Path(base_dir / user_dir).expanduser().resolve()
        report_dir = Path(output_dir / "reports")
        log_dir = Path(output_dir / "logs")
        output_dir.mkdir(parents=True, exist_ok=True)          # <-- creates the parent directory folder
        report_dir.mkdir(parents=True, exist_ok=True)          # <-- creates reports directory
        write_logs = self._act_write_logs.isChecked()
        if write_logs:
            log_dir.mkdir(parents=True, exist_ok=True)         # <-- creates logging directory
        # Use a fixed CSV name inside the folder (you can change it later)
        
        executive_report_path = ""
        comp_report_path      = ""
        defensive_report_path = ""
        redteam_report_path   = ""
        error_log_path        = ""
        scan_log_path         = ""
        if generate_executive_report:
            out_base = Path(out_path)
            csv_path              = report_dir / str(out_base.with_name(f"{out_base.stem}.csv"))
            executive_report_path = report_dir / str(out_base.with_name(f"{out_base.stem}_executive_report.html"))
            comp_report_path      = report_dir / str(out_base.with_name(f"{out_base.stem}_technical_report.html"))
            defensive_report_path = comp_report_path   # same file — defensive IS the technical report
            redteam_report_path   = report_dir / str(out_base.with_name(f"{out_base.stem}_redteam_report.html"))
            if write_logs:
                error_log_path = log_dir / str(out_base.with_name(f"{out_base.stem}_error.log"))
                scan_log_path  = log_dir / str(out_base.with_name(f"{out_base.stem}_scan.log"))
        try:
            software = parse_software_input(sw_path)
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Failed to parse software list:\n{exc}")
            return
        if not software:
            QMessageBox.warning(self, "Warning", "Software list is empty.")
            return

        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.skip_btn.setEnabled(True)
        self.scan_btn.setText("Scanning …")
        self.log.clear()
        self.progress_bar.setValue(0)
        self.progress_label.setText("")
        kev_path = self.kev_row.text()
        cpe_path = self.cpe_row.text()
        api_key = self.api_input.text().strip()
        otx_api_key = self.otx_input.text().strip()
        resources_dir = self.resources_row.text()
 
        self._append_log(f"Starting scan of {len(software)} entries …", "info")
        self._update_status(f"Starting scan of {len(software)} entries …")
        self.worker = ScanWorker(
            software, kev_path, api_key, csv_path, cpe_path,
            show_medium=self.chk_medium.isChecked(),
            show_low=self.chk_low.isChecked(),
            resources_dir=resources_dir,
            executive_report_path=executive_report_path,
            comp_report_path=comp_report_path,
            error_log_path=error_log_path,
            scan_log_path=scan_log_path,
            write_logs=write_logs,
            defensive_report_path=defensive_report_path,
            redteam_report_path=redteam_report_path,
            otx_api_key=otx_api_key,
            input_file=sw_path,
            system_id=extract_system_id(sw_path) if HAS_CACHE else "",
            software_tags=self._tags,
        )
        self.worker.log_signal.connect(self._append_log) 
        self.worker.progress_signal.connect(self._update_progress)
        self.worker.status_signal.connect(self._update_status)
        self.worker.finished_signal.connect(self._scan_finished)
        self.worker.start()

    # ------------------------------------------------------------------
    # Results browser
    # ------------------------------------------------------------------
    def _populate_results_table(self, rows: List[Dict[str, Any]]) -> None:
        from PyQt6.QtWidgets import QTableWidgetItem
        from PyQt6.QtGui import QColor
        self._results_table.setSortingEnabled(False)
        self._results_table.setRowCount(0)
        sev_colors = {
            "CRITICAL": C.RED, "HIGH": C.ORANGE,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN,
        }
        for row in rows:
            ri = self._results_table.rowCount()
            self._results_table.insertRow(ri)
            sev = str(row.get("CVSS Severity","") or "").upper()
            kev = str(row.get("Known Exploited Vulnerability","")).upper() == "YES"
            vals = [
                row.get("CVE ID",""),
                f"{row.get('Software Name','')} {row.get('Software Version','')}".strip(),
                sev,
                str(row.get("Risk Score","")),
                str(row.get("CVSS Base Score","")),
                "⚠ YES" if kev else "No",
                "Yes" if str(row.get("Public Exploit","")).upper() == "YES" else "No",
                str(row.get("EPSS Score","")),
            ]
            for ci, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if ci == 2 and sev in sev_colors:
                    item.setForeground(QColor(sev_colors[sev]))
                if kev and ci == 5:
                    item.setForeground(QColor(C.RED))
                self._results_table.setItem(ri, ci, item)
        self._results_table.setSortingEnabled(True)
        self._results_table.resizeColumnsToContents()

    def _apply_results_filter(self) -> None:
        text    = self._results_filter.text().lower().strip()
        sev_f   = self._sev_filter.currentText()
        kev_f   = self._kev_filter.isChecked()
        for ri in range(self._results_table.rowCount()):
            show = True
            if text:
                row_text = " ".join(
                    self._results_table.item(ri, ci).text().lower()
                    for ci in range(self._results_table.columnCount())
                    if self._results_table.item(ri, ci)
                )
                if text not in row_text:
                    show = False
            if sev_f != "All" and show:
                sev_item = self._results_table.item(ri, 2)
                if sev_item and sev_item.text().upper() != sev_f:
                    show = False
            if kev_f and show:
                kev_item = self._results_table.item(ri, 5)
                if kev_item and "YES" not in kev_item.text().upper():
                    show = False
            self._results_table.setRowHidden(ri, not show)

    def _on_result_row_selected(self, current_row: int) -> None:
        if current_row < 0 or not self._scan_rows:
            return
        # Find the matching row from _scan_rows by CVE ID
        cve_item = self._results_table.item(current_row, 0)
        if not cve_item:
            return
        cve_id = cve_item.text()
        row = next((r for r in self._scan_rows if r.get("CVE ID","") == cve_id), None)
        if row:
            self._detail_panel.setHtml(self._render_cve_detail(row))

    def _render_cve_detail(self, row: Dict[str, Any]) -> str:
        """Render a rich HTML CVE detail card for the detail panel."""
        cid     = row.get("CVE ID","")
        sev     = str(row.get("CVSS Severity","") or "").upper()
        score   = row.get("CVSS Base Score","")
        rs      = row.get("Risk Score","")
        epss    = row.get("EPSS Score","")
        desc    = str(row.get("Description","") or "No description.")
        kev     = str(row.get("Known Exploited Vulnerability","")).upper() == "YES"
        expl    = str(row.get("Public Exploit","")).upper() == "YES"
        expl_src= row.get("Exploit Sources","")
        vector  = row.get("CVSS Vector","")
        cwes    = row.get("CWE","")
        attacks = row.get("ATT&CK Techniques","")
        ics_att = row.get("ICS ATT&CK Techniques","")
        d3fend  = row.get("D3FEND Countermeasures","")
        nist    = row.get("NIST 800-53 Controls","")
        nvd_url = row.get("NVD URL","") or f"https://nvd.nist.gov/vuln/detail/{cid}"
        adv_url = row.get("Vendor Advisory URL","")
        adv_nm  = row.get("Vendor Advisory Name","")
        pub     = row.get("Publisher","")
        idate   = row.get("Install Date","")
        patch_age = row.get("Patch Age (Days)","")
        conf    = row.get("Version Confirmed","")
        sev_color = {
            "CRITICAL": C.RED, "HIGH": C.ORANGE,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN,
        }.get(sev, C.FG_DIM)

        h = html.escape
        lines = [
            f'<div style="font-family:Segoe UI,sans-serif;font-size:12px;color:{C.FG};">',
            f'<h2 style="color:{sev_color};margin:0 0 4px 0;font-size:16px;">'
            f'<a href="{h(nvd_url)}" style="color:{sev_color};text-decoration:none;">'
            f'{h(cid)}</a></h2>',
            f'<div style="color:{C.FG_DIM};font-size:10px;margin-bottom:10px;">'
            f'CVSS {score} ({sev}) &nbsp;|&nbsp; Risk Score: {rs} &nbsp;|&nbsp; EPSS: {epss}</div>',
        ]
        if kev:
            lines.append(f'<div style="background:#3a0a0a;color:{C.RED};padding:4px 8px;'
                         f'border-radius:4px;margin-bottom:6px;font-size:11px;font-weight:700;">'
                         f'⚠ CISA KEV-LISTED — Active exploitation confirmed</div>')
        if expl:
            lines.append(f'<div style="background:#2a1000;color:{C.ORANGE};padding:4px 8px;'
                         f'border-radius:4px;margin-bottom:6px;font-size:11px;font-weight:700;">'
                         f'🔴 PUBLIC EXPLOIT — {h(expl_src or "See NVD")}</div>')
        lines.append(f'<p style="margin:8px 0;line-height:1.5;">{h(desc)}</p>')

        def _section(title: str, content: str) -> str:
            return (f'<div style="margin:8px 0;">'
                    f'<div style="color:{C.FG_DIM};font-size:10px;font-weight:600;'
                    f'letter-spacing:1px;margin-bottom:3px;">{title}</div>'
                    f'<div style="font-size:11px;color:{C.FG};">{content}</div></div>')

        def _link(url: str, label: str) -> str:
            return f'<a href="{h(url)}" style="color:{C.BLUE};">{h(label)}</a>'

        if vector:
            lines.append(_section("CVSS VECTOR", f'<code style="color:{C.YELLOW}">{h(vector)}</code>'))
        if cwes:
            cwe_links = " ".join(
                _link(f"https://cwe.mitre.org/data/definitions/{c.replace('CWE-','')}.html", c)
                for c in cwes.split(";") if c.strip()
            )
            lines.append(_section("CWE", cwe_links))
        if attacks:
            atk_parts = []
            for atk in attacks.split(";"):
                atk = atk.strip()
                import re as _re
                m = _re.match(r"(T\d{4}(?:\.\d{3})?)\s*\((.*?)\)$", atk)
                if m:
                    tid, tname = m.group(1), m.group(2)
                    atk_parts.append(_link(
                        f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/",
                        f"{tid} {tname}"
                    ))
                else:
                    atk_parts.append(h(atk))
            lines.append(_section("ATT&CK TECHNIQUES", " &nbsp;·&nbsp; ".join(atk_parts)))
        if ics_att:
            ics_parts = []
            for atk in ics_att.split(";"):
                atk = atk.strip()
                import re as _re2
                m2 = _re2.match(r"(T\d{4})\s*\((.*?)\)$", atk)
                if m2:
                    tid, tname = m2.group(1), m2.group(2)
                    ics_parts.append(_link(
                        f"https://attack.mitre.org/techniques/{tid}/",
                        f"{tid} {tname} (ICS)"
                    ))
                else:
                    ics_parts.append(h(atk))
            lines.append(_section("ICS ATT&CK TECHNIQUES", " &nbsp;·&nbsp; ".join(ics_parts)))
        if d3fend:
            d3_parts = []
            for cm in d3fend.split(";"):
                cm = cm.strip()
                if cm:
                    slug = cm.replace(" ","")
                    d3_parts.append(_link(f"https://d3fend.mitre.org/technique/d3f:{slug}/", cm))
            lines.append(_section("D3FEND COUNTERMEASURES", " &nbsp;·&nbsp; ".join(d3_parts)))
        if nist:
            nist_parts = []
            for ctrl in nist.split(";"):
                ctrl = ctrl.strip()
                ctrl_id = ctrl.split()[0] if ctrl.split() else ctrl
                nist_parts.append(_link(
                    f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={ctrl_id}",
                    ctrl_id
                ))
            lines.append(_section("NIST 800-53 CONTROLS", " &nbsp;·&nbsp; ".join(nist_parts)))

        meta_parts = []
        if pub:    meta_parts.append(f"Publisher: {h(pub)}")
        if idate:  meta_parts.append(f"Installed: {h(idate)}")
        if patch_age: meta_parts.append(f"Patch Age: {h(patch_age)} days")
        if conf:   meta_parts.append(f"Version Confirmed: {h(conf)}")
        if meta_parts:
            lines.append(_section("INVENTORY", " &nbsp;|&nbsp; ".join(meta_parts)))

        # Links
        link_parts = [_link(nvd_url, "NVD Advisory")]
        if adv_url:
            link_parts.append(_link(adv_url, adv_nm or "Vendor Advisory"))
        lines.append(_section("REFERENCES", " &nbsp;|&nbsp; ".join(link_parts)))
        lines.append("</div>")
        return "".join(lines)

    # ------------------------------------------------------------------
    # Version check
    # ------------------------------------------------------------------
    def _check_version(self) -> None:
        try:
            update = check_for_update()
            if update:
                self._append_log(
                    f"🔔 Update available: Draugr v{update['version']} — {update['url']}",
                    "warn"
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Load CSV into Results Browser
    # ------------------------------------------------------------------
    def _load_csv_into_browser(self) -> None:
        """Load a previously saved Draugr scan CSV into the Results Browser."""
        if not HAS_DIFF:
            # load_scan_csv lives in draugr_diff — fall back to built-in csv if missing
            import csv as _csv
            path, _ = QFileDialog.getOpenFileName(
                self, "Open Draugr Scan CSV", "", "CSV files (*.csv);;All files (*)"
            )
            if not path:
                return
            try:
                rows = []
                with open(path, newline="", encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        rows.append(dict(row))
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Could not read CSV:\n{e}")
                return
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open Draugr Scan CSV", "", "CSV files (*.csv);;All files (*)"
            )
            if not path:
                return
            try:
                rows = load_scan_csv(path)
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Could not read CSV:\n{e}")
                return

        if not rows:
            QMessageBox.warning(self, "Empty File", "No data found in the selected CSV.")
            return

        self._scan_rows = rows
        self._populate_results_table(self._scan_rows)

        # Update source label
        import datetime as _dt
        filename = Path(path).name
        mod_time = _dt.datetime.fromtimestamp(Path(path).stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        self._results_source_label.setText(
            f"{filename}  —  {mod_time}  —  {len(rows)} finding(s)"
        )
        self.tab_widget.setCurrentIndex(1)
        self._append_log(
            f"📂 Loaded {len(rows)} findings from {filename}", "ok"
        )

    # ------------------------------------------------------------------
    # Stop / Skip scan
    # ------------------------------------------------------------------
    def _stop_scan(self) -> None:
        if self.worker:
            self._append_log("Stop requested ...", "info")
            self.worker.requestInterruption()
            self.stop_btn.setEnabled(False)
            self.skip_btn.setEnabled(False)

    def _skip_current_software(self) -> None:
        """Signal the worker to abandon the current software item and move to the next."""
        if self.worker and self.scanning:
            self.worker._skip_current = True
            self._append_log(
                "⏭ Skip requested — current item will be skipped after the active network call completes.",
                "warn",
            )

    # ------------------------------------------------------------------
    # Diff / Compare Scans
    # ------------------------------------------------------------------
    def _run_diff(self):
        if not HAS_DIFF:
            QMessageBox.warning(self, "Unavailable",
                "draugr_diff.py not found. Place it in the same directory as draugr.py.")
            return

        old_path, _ = QFileDialog.getOpenFileName(
            self, "Select Previous Scan CSV", "", "CSV files (*.csv);;All files (*)"
        )
        if not old_path:
            return
        new_path, _ = QFileDialog.getOpenFileName(
            self, "Select Current Scan CSV", "", "CSV files (*.csv);;All files (*)"
        )
        if not new_path:
            return
        out_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not out_dir:
            return

        try:
            old_rows = load_scan_csv(old_path)
            new_rows = load_scan_csv(new_path)
            diff     = compute_diff(old_rows, new_rows)
            stats    = diff["stats"]

            stem          = Path(new_path).stem
            diff_html     = Path(out_dir) / f"{stem}_diff.html"
            diff_csv_out  = Path(out_dir) / f"{stem}_diff.csv"

            with open(diff_html, "w", encoding="utf-8") as f:
                f.write(build_diff_report(
                    diff,
                    old_label=Path(old_path).name,
                    new_label=Path(new_path).name,
                ))
            n_csv = export_diff_csv(diff, str(diff_csv_out))

            QMessageBox.information(self, "Diff Complete",
                f"Delta report generated:\n\n"
                f"  New findings:  {stats['new_findings']}\n"
                f"  Resolved:      {stats['resolved']}\n"
                f"  Worsened:      {stats['worsened']}\n"
                f"  Improved:      {stats['improved']}\n"
                f"  Newly KEV:     {stats['newly_kev']}\n\n"
                f"HTML: {diff_html}\n"
                f"CSV:  {diff_csv_out}"
            )
            self._append_log(
                f"Δ Diff complete: {stats['new_findings']} new, {stats['resolved']} resolved → {diff_html}",
                "ok"
            )
        except Exception as e:
            QMessageBox.critical(self, "Diff Error", str(e))

    # ------------------------------------------------------------------
    # False Positive Manager
    # ------------------------------------------------------------------
    def _manage_false_positives(self):
        if not HAS_CACHE:
            QMessageBox.warning(self, "Unavailable",
                "draugr_cache.py not found. Place it in the same directory as draugr.py.")
            return

        try:
            db  = _get_db()
            fps = db.all_false_positives()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load false positives:\n{e}")
            return

        from PyQt6.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QDialogButtonBox

        dlg = QDialog(self)
        dlg.setWindowTitle("False Positive Suppression List")
        dlg.setMinimumSize(720, 400)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")

        layout = QVBoxLayout(dlg)

        info = QLabel(
            "CVEs in this list are suppressed and will not appear in scan results.\n"
            "Add entries manually or import from a JSON file."
        )
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        layout.addWidget(info)

        table = QTableWidget(len(fps), 3)
        table.setHorizontalHeaderLabels(["CVE ID", "Software Name", "Reason"])
        table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_CARD}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; gridline-color:{C.BORDER}; }}"
            f"QHeaderView::section {{ background:{C.BG_INPUT}; color:{C.FG_DIM}; "
            f"border:1px solid {C.BORDER}; padding:4px; }}"
        )
        table.horizontalHeader().setStretchLastSection(True)
        for row_i, fp in enumerate(fps):
            table.setItem(row_i, 0, QTableWidgetItem(fp["cve_id"]))
            table.setItem(row_i, 1, QTableWidgetItem(fp["sw_name"]))
            table.setItem(row_i, 2, QTableWidgetItem(fp.get("reason", "")))
        layout.addWidget(table)

        btn_layout = QHBoxLayout()

        def _add_fp():
            cve_id, ok1 = __import__("PyQt6.QtWidgets", fromlist=["QInputDialog"]).QInputDialog.getText(
                dlg, "Add False Positive", "CVE ID (e.g. CVE-2024-12345):"
            )
            if not ok1 or not cve_id.strip():
                return
            sw_name, ok2 = __import__("PyQt6.QtWidgets", fromlist=["QInputDialog"]).QInputDialog.getText(
                dlg, "Add False Positive", "Software name:"
            )
            if not ok2:
                return
            reason, _ = __import__("PyQt6.QtWidgets", fromlist=["QInputDialog"]).QInputDialog.getText(
                dlg, "Add False Positive", "Reason (optional):"
            )
            try:
                db.add_false_positive(cve_id.strip(), sw_name.strip(), reason.strip())
                self._append_log(f"False positive added: {cve_id.strip()} / {sw_name.strip()}", "ok")
                dlg.accept()
                self._manage_false_positives()
            except Exception as e:
                QMessageBox.critical(dlg, "Error", str(e))

        def _import_fp():
            path, _ = QFileDialog.getOpenFileName(
                dlg, "Import False Positives JSON", "", "JSON files (*.json)"
            )
            if not path:
                return
            try:
                n = db.import_false_positives(path)
                QMessageBox.information(dlg, "Import Complete", f"Imported {n} entries.")
                dlg.accept()
                self._manage_false_positives()
            except Exception as e:
                QMessageBox.critical(dlg, "Import Error", str(e))

        def _export_fp():
            path, _ = QFileDialog.getSaveFileName(
                dlg, "Export False Positives JSON", "false_positives.json", "JSON files (*.json)"
            )
            if not path:
                return
            try:
                n = db.export_false_positives(path)
                QMessageBox.information(dlg, "Export Complete", f"Exported {n} entries to:\n{path}")
            except Exception as e:
                QMessageBox.critical(dlg, "Export Error", str(e))

        btn_style = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                     f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 12px; }}"
                     f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")

        for label, slot in [("Add Entry", _add_fp), ("Import JSON", _import_fp), ("Export JSON", _export_fp)]:
            btn = QPushButton(label)
            btn.setStyleSheet(btn_style)
            btn.clicked.connect(slot)
            btn_layout.addWidget(btn)

        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(btn_style)
        close_btn.clicked.connect(dlg.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        dlg.exec()

    # ------------------------------------------------------------------
    # Scan History / Trend viewer
    # ------------------------------------------------------------------
    def _view_scan_history(self):
        if not HAS_CACHE:
            QMessageBox.warning(self, "Unavailable",
                "draugr_cache.py not found. Place it in the same directory as draugr.py.")
            return
        try:
            db      = _get_db()
            systems = db.get_all_systems()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load scan history:\n{e}")
            return

        from PyQt6.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QComboBox

        dlg = QDialog(self)
        dlg.setWindowTitle("Scan History & Trend Tracking")
        dlg.setMinimumSize(860, 500)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)

        info = QLabel(f"{len(systems)} system(s) tracked in scan history database.")
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        layout.addWidget(info)

        sel_row = QHBoxLayout()
        sel_lbl = QLabel("System:")
        sel_lbl.setStyleSheet(f"color:{C.FG_DIM}; font-size:12px;")
        combo   = QComboBox()
        combo.setStyleSheet(
            f"QComboBox {{ background:{C.BG_INPUT}; color:{C.FG}; border:1px solid {C.BORDER}; "
            f"border-radius:4px; padding:4px 8px; }}"
        )
        for s in systems:
            combo.addItem(f"{s['system_label']} ({s['scan_count']} scans)", s["system_id"])
        sel_row.addWidget(sel_lbl)
        sel_row.addWidget(combo, 1)
        layout.addLayout(sel_row)

        table = QTableWidget(0, 7)
        table.setHorizontalHeaderLabels([
            "Scan Date", "Total CVEs", "Critical", "High", "KEV", "Max Risk", "Input File"
        ])
        table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_CARD}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; gridline-color:{C.BORDER}; }}"
            f"QHeaderView::section {{ background:{C.BG_INPUT}; color:{C.FG_DIM}; "
            f"border:1px solid {C.BORDER}; padding:4px; }}"
        )
        table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(table)

        def _load_history(idx: int):
            sid  = combo.itemData(idx)
            hist = db.get_scan_history(sid, limit=30)
            table.setRowCount(len(hist))
            for row_i, h in enumerate(hist):
                table.setItem(row_i, 0, QTableWidgetItem(h.get("scan_date","")))
                table.setItem(row_i, 1, QTableWidgetItem(str(h.get("total_cves",0))))
                table.setItem(row_i, 2, QTableWidgetItem(str(h.get("critical",0))))
                table.setItem(row_i, 3, QTableWidgetItem(str(h.get("high",0))))
                table.setItem(row_i, 4, QTableWidgetItem(str(h.get("kev_count",0))))
                table.setItem(row_i, 5, QTableWidgetItem(f"{h.get('max_risk',0.0):.1f}"))
                table.setItem(row_i, 6, QTableWidgetItem(
                    str(Path(h.get("input_file","")).name)
                ))

        combo.currentIndexChanged.connect(_load_history)
        if systems:
            _load_history(0)

        btn_layout = QHBoxLayout()
        btn_style  = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                      f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 12px; }}"
                      f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")

        def _export_fleet():
            if not HAS_FLEET:
                QMessageBox.warning(dlg, "Unavailable", "draugr_fleet.py not found.")
                return
            path, _ = QFileDialog.getSaveFileName(
                dlg, "Save Fleet Report", "draugr_fleet_report.html", "HTML files (*.html)"
            )
            if not path:
                return
            try:
                fleet_html = build_fleet_report_from_db(db)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(fleet_html)
                QMessageBox.information(dlg, "Export Complete", f"Fleet report saved:\n{path}")
            except Exception as e:
                QMessageBox.critical(dlg, "Export Error", str(e))

        fleet_btn = QPushButton("Export Fleet Report")
        fleet_btn.setStyleSheet(btn_style)
        fleet_btn.clicked.connect(_export_fleet)
        btn_layout.addWidget(fleet_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(btn_style)
        close_btn.clicked.connect(dlg.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        dlg.exec()

    # ------------------------------------------------------------------
    # Alert configuration
    # ------------------------------------------------------------------
    def _configure_alerts(self):
        if not HAS_ALERTS:
            QMessageBox.warning(self, "Unavailable",
                "draugr_alerts.py not found. Place it in the same directory as draugr.py.")
            return

        from PyQt6.QtWidgets import QDialog

        cfg = load_alert_config()
        dlg = QDialog(self)
        dlg.setWindowTitle("Alert Configuration")
        dlg.setMinimumSize(540, 580)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)

        lbl_style  = f"color:{C.FG_DIM}; font-size:11px;"
        field_style = (f"QLineEdit {{ background:{C.BG_INPUT}; color:{C.FG}; "
                       f"border:1px solid {C.BORDER}; border-radius:4px; padding:4px 8px; }}"
                       f"QCheckBox {{ color:{C.FG_DIM}; font-size:12px; }}")

        def _section(title: str):
            lbl = QLabel(title)
            lbl.setStyleSheet(f"color:{C.ACCENT}; font-size:11px; font-weight:600; "
                              f"letter-spacing:1px; padding-top:10px;")
            layout.addWidget(lbl)

        def _field(label: str, value: str, placeholder: str = "", password: bool = False) -> QLineEdit:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(160)
            lbl.setStyleSheet(lbl_style)
            inp = QLineEdit(value)
            inp.setPlaceholderText(placeholder)
            inp.setStyleSheet(field_style)
            if password:
                inp.setEchoMode(QLineEdit.EchoMode.Password)
            row.addWidget(lbl)
            row.addWidget(inp, 1)
            layout.addLayout(row)
            return inp

        def _check(label: str, checked: bool) -> QCheckBox:
            cb = QCheckBox(label)
            cb.setChecked(checked)
            cb.setStyleSheet(field_style)
            layout.addWidget(cb)
            return cb

        _section("GENERAL")
        chk_enabled    = _check("Enable alerting", cfg.get("enabled", False))
        chk_kev        = _check("Alert on KEV findings", cfg.get("alert_on_kev", True))
        chk_new_system = _check("Alert on new system (first scan)", cfg.get("alert_on_new_system", True))

        _section("SMTP EMAIL")
        chk_smtp = _check("Enable email alerts", cfg.get("smtp",{}).get("enabled", False))
        f_host   = _field("SMTP Host",      cfg.get("smtp",{}).get("host",""),     "smtp.gmail.com")
        f_port   = _field("SMTP Port",      str(cfg.get("smtp",{}).get("port",587)), "587")
        f_user   = _field("Username",       cfg.get("smtp",{}).get("username",""), "you@example.com")
        f_pass   = _field("Password",       cfg.get("smtp",{}).get("password",""), "", password=True)
        f_from   = _field("From",           cfg.get("smtp",{}).get("from_addr",""), "draugr@example.com")
        f_to     = _field("To (comma-sep)", ", ".join(cfg.get("smtp",{}).get("to_addrs",[])), "a@b.com, c@d.com")

        _section("WEBHOOK")
        chk_wh    = _check("Enable webhook alerts", cfg.get("webhook",{}).get("enabled", False))
        f_url     = _field("Webhook URL",   cfg.get("webhook",{}).get("url",""),   "https://hooks.slack.com/...")
        f_wh_type = _field("Type",          cfg.get("webhook",{}).get("type","slack"), "slack / teams / generic")
        f_mention = _field("Mention",       cfg.get("webhook",{}).get("mention",""), "@channel")

        btn_layout = QHBoxLayout()
        btn_style  = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                      f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 14px; }}"
                      f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")

        def _save():
            to_list = [a.strip() for a in f_to.text().split(",") if a.strip()]
            new_cfg = {
                "enabled":             chk_enabled.isChecked(),
                "alert_on_kev":        chk_kev.isChecked(),
                "alert_on_new_system": chk_new_system.isChecked(),
                "risk_threshold":      cfg.get("risk_threshold", 80.0),
                "kev_threshold":       cfg.get("kev_threshold", 1),
                "smtp": {
                    "enabled":   chk_smtp.isChecked(),
                    "host":      f_host.text().strip(),
                    "port":      int(f_port.text().strip() or 587),
                    "use_tls":   True,
                    "username":  f_user.text().strip(),
                    "password":  f_pass.text(),
                    "from_addr": f_from.text().strip(),
                    "to_addrs":  to_list,
                },
                "webhook": {
                    "enabled": chk_wh.isChecked(),
                    "url":     f_url.text().strip(),
                    "type":    f_wh_type.text().strip() or "generic",
                    "headers": {},
                    "mention": f_mention.text().strip(),
                },
            }
            try:
                from draugr_alerts import save_alert_config
                save_alert_config(new_cfg)
                QMessageBox.information(dlg, "Saved", "Alert configuration saved.")
                dlg.accept()
            except Exception as e:
                QMessageBox.critical(dlg, "Save Error", str(e))

        save_btn  = QPushButton("Save")
        save_btn.setStyleSheet(btn_style)
        save_btn.clicked.connect(_save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(btn_style)
        cancel_btn.clicked.connect(dlg.reject)
        btn_layout.addStretch()
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        dlg.exec()


    # ------------------------------------------------------------------
    # Theme switcher
    # ------------------------------------------------------------------
    def _change_theme(self) -> None:
        if not HAS_THEMES:
            QMessageBox.information(self, "Theme", "draugr_themes.py not found — using default theme.")
            return
        from PyQt6.QtWidgets import QDialog, QListWidget
        dlg = QDialog(self)
        dlg.setWindowTitle("Select Theme")
        dlg.setFixedSize(300, 200)
        layout = QVBoxLayout(dlg)
        lw = QListWidget()
        lw.setStyleSheet(
            f"QListWidget {{ background:{C.BG_INPUT}; color:{C.FG}; border:1px solid {C.BORDER}; }}"
            f"QListWidget::item:selected {{ background:{C.ACCENT}; }}"
        )
        from draugr_themes import THEMES, get_theme_name
        current = get_theme_name()
        for key, th in THEMES.items():
            lw.addItem(th["name"])
            if key == current:
                lw.setCurrentRow(lw.count() - 1)
        layout.addWidget(QLabel("Select a theme (takes effect on restart):"))
        layout.addWidget(lw)
        btn_layout = QHBoxLayout()
        btn_s = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                 f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 14px; }}"
                 f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")
        ok_btn = QPushButton("Apply")
        ok_btn.setStyleSheet(btn_s)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(btn_s)
        btn_layout.addStretch()
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        cancel_btn.clicked.connect(dlg.reject)
        def _apply():
            idx = lw.currentRow()
            if idx >= 0:
                key = list(THEMES.keys())[idx]
                set_theme(key)
                QMessageBox.information(dlg, "Theme", f"Theme set to '{THEMES[key]['name']}'. Restart Draugr to apply.")
            dlg.accept()
        ok_btn.clicked.connect(_apply)
        dlg.exec()

    # ------------------------------------------------------------------
    # CPE confidence threshold
    # ------------------------------------------------------------------
    def _set_confidence_threshold(self) -> None:
        global _CPE_CONFIDENCE_THRESHOLD
        from PyQt6.QtWidgets import QDialog, QSlider, QDoubleSpinBox
        dlg = QDialog(self)
        dlg.setWindowTitle("CPE Confidence Threshold")
        dlg.setFixedSize(380, 200)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)
        info = QLabel(
            "Set the minimum CPE match confidence required for a CVE to be included in results.\n\n"
            "Lower = more results, more false positives.\n"
            "Higher = fewer results, fewer false positives.\n"
            f"Current: {_CPE_CONFIDENCE_THRESHOLD:.0%}"
        )
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        info.setWordWrap(True)
        layout.addWidget(info)
        spin = QDoubleSpinBox()
        spin.setRange(0.0, 0.5)
        spin.setSingleStep(0.01)
        spin.setDecimals(2)
        spin.setValue(_CPE_CONFIDENCE_THRESHOLD)
        spin.setStyleSheet(
            f"QDoubleSpinBox {{ background:{C.BG_INPUT}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; border-radius:4px; padding:4px 8px; }}"
        )
        layout.addWidget(spin)
        btn_s = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                 f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 14px; }}"
                 f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("Apply")
        ok_btn.setStyleSheet(btn_s)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(btn_s)
        btn_layout.addStretch()
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        cancel_btn.clicked.connect(dlg.reject)
        def _apply():
            _CPE_CONFIDENCE_THRESHOLD = spin.value()
            if HAS_CACHE:
                try:
                    prefs = {}
                    from draugr_cache import _default_cache_dir
                    p = _default_cache_dir() / "prefs.json"
                    if p.exists():
                        import json as _j
                        prefs = _j.loads(p.read_text())
                    prefs["cpe_confidence"] = _CPE_CONFIDENCE_THRESHOLD
                    p.write_text(import_json := __import__("json").dumps(prefs, indent=2))
                except Exception:
                    pass
            self._append_log(f"CPE confidence threshold set to {_CPE_CONFIDENCE_THRESHOLD:.0%}", "ok")
            dlg.accept()
        ok_btn.clicked.connect(_apply)
        dlg.exec()

    # ------------------------------------------------------------------
    # CPE mappings editor
    # ------------------------------------------------------------------
    def _edit_cpe_mappings(self) -> None:
        from PyQt6.QtWidgets import QDialog, QTableWidget, QTableWidgetItem
        dlg = QDialog(self)
        dlg.setWindowTitle("CPE Mappings Editor")
        dlg.setMinimumSize(700, 420)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)

        info = QLabel(
            "Learned CPE mappings (auto-saved from high-confidence scans) "
            "and manual cpe_mappings.json entries. "
            "Edit the 'CPE String' column to correct a mapping; delete rows to remove them."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        layout.addWidget(info)

        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Software Name", "CPE String", "Confidence", "Hit Count"])
        table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_CARD}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; gridline-color:{C.BORDER}; }}"
            f"QHeaderView::section {{ background:{C.BG_INPUT}; color:{C.FG_DIM}; "
            f"border:1px solid {C.BORDER}; padding:4px; }}"
        )
        table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(table)

        # Load learned mappings
        entries = []
        if HAS_CACHE:
            try:
                db = _get_db()
                entries = db.get_all_learned_cpes()
            except Exception:
                pass
        # Also load manual cpe_mappings.json
        try:
            if os.path.isfile(CPE_MAPPING_DEFAULT):
                with open(CPE_MAPPING_DEFAULT, "r", encoding="utf-8") as f:
                    manual = json.load(f)
                for k, v in manual.items():
                    if not any(e["sw_key"] == k for e in entries):
                        entries.append({"sw_key": k, "cpe_string": v, "confidence": 1.0, "hit_count": "manual"})
        except Exception:
            pass

        for e in entries:
            ri = table.rowCount()
            table.insertRow(ri)
            table.setItem(ri, 0, QTableWidgetItem(e["sw_key"]))
            table.setItem(ri, 1, QTableWidgetItem(e["cpe_string"]))
            table.setItem(ri, 2, QTableWidgetItem(f"{e['confidence']:.0%}" if isinstance(e['confidence'], float) else str(e['confidence'])))
            table.setItem(ri, 3, QTableWidgetItem(str(e["hit_count"])))
        table.resizeColumnsToContents()

        btn_s = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                 f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 12px; }}"
                 f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")
        btn_layout = QHBoxLayout()

        def _export():
            path, _ = QFileDialog.getSaveFileName(dlg, "Export learned CPEs", "cpe_learned.json", "JSON (*.json)")
            if path and HAS_CACHE:
                try:
                    n = _get_db().export_learned_cpes(path)
                    QMessageBox.information(dlg, "Export", f"Exported {n} entries.")
                except Exception as e:
                    QMessageBox.critical(dlg, "Error", str(e))

        export_btn = QPushButton("Export as JSON")
        export_btn.setStyleSheet(btn_s)
        export_btn.clicked.connect(_export)
        btn_layout.addWidget(export_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(btn_s)
        close_btn.clicked.connect(dlg.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        dlg.exec()

    # ------------------------------------------------------------------
    # Scan profiles
    # ------------------------------------------------------------------
    def _manage_profiles(self) -> None:
        from PyQt6.QtWidgets import QDialog, QListWidget, QListWidgetItem
        dlg = QDialog(self)
        dlg.setWindowTitle("Scan Profiles")
        dlg.setMinimumSize(500, 360)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)
        info = QLabel("Save the current configuration as a named profile, or load a saved profile.")
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        layout.addWidget(info)

        lw = QListWidget()
        lw.setStyleSheet(
            f"QListWidget {{ background:{C.BG_CARD}; color:{C.FG}; border:1px solid {C.BORDER}; }}"
            f"QListWidget::item:selected {{ background:{C.ACCENT}; color:#fff; }}"
        )
        for name in sorted(self._profiles.keys()):
            lw.addItem(name)
        layout.addWidget(lw)

        btn_s = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                 f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 12px; }}"
                 f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")
        btn_layout = QHBoxLayout()

        def _save_profile():
            from PyQt6.QtWidgets import QInputDialog
            name, ok = QInputDialog.getText(dlg, "Save Profile", "Profile name:")
            if not ok or not name.strip():
                return
            self._profiles[name.strip()] = {
                "sw_path":       self.sw_row.text(),
                "out_path":      self.out_row.text(),
                "kev_path":      self.kev_row.text(),
                "cpe_path":      self.cpe_row.text(),
                "resources_dir": self.resources_row.text(),
                "api_key":       "",    # never save API keys in profiles
                "show_medium":   self.chk_medium.isChecked(),
                "show_low":      self.chk_low.isChecked(),
            }
            self._save_profiles()
            lw.clear()
            for n in sorted(self._profiles.keys()):
                lw.addItem(n)
            self._append_log(f"Profile saved: {name.strip()}", "ok")

        def _load_profile():
            items = lw.selectedItems()
            if not items:
                return
            name = items[0].text()
            p = self._profiles.get(name, {})
            if p.get("sw_path"):
                self.sw_row.setText(p["sw_path"])
            if p.get("out_path"):
                self.out_row.setText(p["out_path"])
            if p.get("kev_path"):
                self.kev_row.setText(p["kev_path"])
            if p.get("cpe_path"):
                self.cpe_row.setText(p["cpe_path"])
            if p.get("resources_dir"):
                self.resources_row.setText(p["resources_dir"])
            self.chk_medium.setChecked(p.get("show_medium", True))
            self.chk_low.setChecked(p.get("show_low", False))
            self._append_log(f"Profile loaded: {name}", "ok")
            dlg.accept()

        def _delete_profile():
            items = lw.selectedItems()
            if not items:
                return
            name = items[0].text()
            self._profiles.pop(name, None)
            self._save_profiles()
            for i in range(lw.count()):
                if lw.item(i).text() == name:
                    lw.takeItem(i)
                    break

        for label, slot in [("Save Current", _save_profile), ("Load", _load_profile), ("Delete", _delete_profile)]:
            btn = QPushButton(label)
            btn.setStyleSheet(btn_s)
            btn.clicked.connect(slot)
            btn_layout.addWidget(btn)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(btn_s)
        close_btn.clicked.connect(dlg.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        dlg.exec()

    # ------------------------------------------------------------------
    # PDF export
    # ------------------------------------------------------------------
    def _export_pdf(self) -> None:
        # Try WeasyPrint first, fall back to instructions
        try:
            import weasyprint
            HAS_WEASYPRINT = True
        except ImportError:
            HAS_WEASYPRINT = False

        if not HAS_WEASYPRINT:
            QMessageBox.information(
                self, "PDF Export",
                "PDF export requires WeasyPrint.\n\n"
                "Install it with:\n  pip install weasyprint\n\n"
                "Alternatively, open any HTML report in your browser and use\n"
                "File → Print → Save as PDF."
            )
            return

        html_path, _ = QFileDialog.getOpenFileName(
            self, "Select HTML Report to Convert", "", "HTML files (*.html)"
        )
        if not html_path:
            return
        pdf_path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF", html_path.replace(".html", ".pdf"), "PDF files (*.pdf)"
        )
        if not pdf_path:
            return
        try:
            import weasyprint as wp
            wp.HTML(filename=html_path).write_pdf(pdf_path)
            QMessageBox.information(self, "PDF Export", f"PDF saved:\n{pdf_path}")
            self._append_log(f"📄 PDF exported → {pdf_path}", "ok")
        except Exception as e:
            QMessageBox.critical(self, "PDF Export Error", str(e))

    # ------------------------------------------------------------------
    # Plugins manager
    # ------------------------------------------------------------------
    def _manage_plugins(self) -> None:
        if not HAS_PLUGINS:
            QMessageBox.warning(self, "Unavailable",
                "draugr_plugins.py not found. Place it in the same directory as draugr.py.")
            return

        from PyQt6.QtWidgets import QDialog, QTableWidget, QTableWidgetItem
        ensure_plugins_dir()

        dlg = QDialog(self)
        dlg.setWindowTitle("Plugins Manager")
        dlg.setMinimumSize(660, 380)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)

        plugins    = get_loaded_plugins()
        errors     = get_load_errors()
        plugins_dir_path = str(Path(os.path.dirname(os.path.abspath(__file__))) / "plugins")

        info = QLabel(
            f"Plugins directory: {plugins_dir_path}\n"
            f"{len(plugins)} plugin(s) loaded. "
            "Drop .py files into the plugins/ directory and restart to add plugins."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        layout.addWidget(info)

        table = QTableWidget(len(plugins), 4)
        table.setHorizontalHeaderLabels(["Name", "Version", "Hooks", "File"])
        table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_CARD}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; gridline-color:{C.BORDER}; }}"
            f"QHeaderView::section {{ background:{C.BG_INPUT}; color:{C.FG_DIM}; "
            f"border:1px solid {C.BORDER}; padding:4px; }}"
        )
        table.horizontalHeader().setStretchLastSection(True)
        for ri, p in enumerate(plugins):
            hooks = ", ".join(h for h in ["enrich_row","score_modifier","on_scan_complete","report_section"]
                              if p.get(h))
            table.setItem(ri, 0, QTableWidgetItem(p["name"]))
            table.setItem(ri, 1, QTableWidgetItem(p["version"]))
            table.setItem(ri, 2, QTableWidgetItem(hooks or "none"))
            table.setItem(ri, 3, QTableWidgetItem(Path(p["file"]).name))
        layout.addWidget(table)

        if errors:
            err_label = QLabel(f"⚠ {len(errors)} plugin(s) failed to load:")
            err_label.setStyleSheet(f"color:{C.RED}; font-size:11px;")
            layout.addWidget(err_label)
            err_box = QTextEdit("\n\n".join(errors))
            err_box.setReadOnly(True)
            err_box.setMaximumHeight(80)
            err_box.setStyleSheet(
                f"QTextEdit {{ background:{C.BG_INPUT}; color:{C.RED}; "
                f"border:1px solid {C.BORDER}; font-size:10px; }}"
            )
            layout.addWidget(err_box)

        btn_s = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                 f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 12px; }}"
                 f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")
        btn_layout = QHBoxLayout()

        def _open_dir():
            import subprocess
            try:
                if os.name == "nt":
                    os.startfile(plugins_dir_path)
                else:
                    subprocess.Popen(["xdg-open", plugins_dir_path])
            except Exception:
                QMessageBox.information(dlg, "Plugins", f"Plugins directory:\n{plugins_dir_path}")

        open_btn = QPushButton("Open Plugins Folder")
        open_btn.setStyleSheet(btn_s)
        open_btn.clicked.connect(_open_dir)
        btn_layout.addWidget(open_btn)

        def _reload():
            load_plugins()
            QMessageBox.information(dlg, "Reload", f"{len(get_loaded_plugins())} plugin(s) loaded.")
            dlg.accept()
            self._manage_plugins()

        reload_btn = QPushButton("Reload Plugins")
        reload_btn.setStyleSheet(btn_s)
        reload_btn.clicked.connect(_reload)
        btn_layout.addWidget(reload_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(btn_s)
        close_btn.clicked.connect(dlg.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        dlg.exec()

    # ------------------------------------------------------------------
    # KEV background check
    # ------------------------------------------------------------------
    def _check_kev_now(self) -> None:
        """
        Fetch the live CISA KEV feed and check if any CVEs from the last scan
        are newly listed (not in the KEV at scan time but now listed).
        """
        if not self._scan_rows:
            QMessageBox.information(self, "KEV Check",
                "No scan results loaded. Run a scan first.")
            return
        try:
            self._append_log("🔄 Fetching live CISA KEV feed…", "info")
            live_kev = fetch_kev_online()
            if not live_kev:
                QMessageBox.warning(self, "KEV Check", "Could not fetch the live KEV feed.")
                return
            scan_cve_ids = {str(r.get("CVE ID","")).upper() for r in self._scan_rows}
            newly_kev    = [
                cid for cid in scan_cve_ids
                if cid in live_kev
                and not any(
                    str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
                    for r in self._scan_rows if r.get("CVE ID","").upper() == cid
                )
            ]
            if newly_kev:
                msg = (
                    f"⚠ {len(newly_kev)} CVE(s) from your last scan have been "
                    f"added to the CISA KEV catalog since the scan was run:\n\n"
                    + "\n".join(f"  • {c}" for c in sorted(newly_kev)[:20])
                )
                self._append_log(msg, "warn")
                QMessageBox.warning(self, "Newly KEV-Listed CVEs", msg)
            else:
                self._append_log("✓ No newly KEV-listed CVEs found in the last scan.", "ok")
                QMessageBox.information(self, "KEV Check",
                    "No new KEV listings found for CVEs in your last scan.")
        except Exception as e:
            self._append_log(f"KEV check error: {e}", "error")
            QMessageBox.critical(self, "KEV Check Error", str(e))


    # ------------------------------------------------------------------
    # Update settings and manual update check
    # ------------------------------------------------------------------
    def _update_settings(self) -> None:
        """Configure the GitHub repository used for update checks."""
        from PyQt6.QtWidgets import QDialog

        dlg = QDialog(self)
        dlg.setWindowTitle("Update Settings")
        dlg.setFixedSize(460, 200)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)

        info = QLabel(
            f"Current version: <b>v{DRAUGR_VERSION}</b><br><br>"
            "Enter your GitHub repository in the format <b>owner/repo</b> "
            "(e.g. <code>jsmith/draugr</code>).<br>"
            "Draugr will check this repository's releases for newer versions."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        info.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info)

        field_row = QHBoxLayout()
        lbl = QLabel("GitHub Repo:")
        lbl.setStyleSheet(f"color:{C.FG_DIM}; font-size:12px;")
        lbl.setFixedWidth(110)
        inp = QLineEdit(_GITHUB_REPO)
        inp.setPlaceholderText("owner/repo  e.g. jsmith/draugr")
        inp.setStyleSheet(
            f"QLineEdit {{ background:{C.BG_INPUT}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; border-radius:4px; padding:5px 8px; }}"
        )
        field_row.addWidget(lbl)
        field_row.addWidget(inp, 1)
        layout.addLayout(field_row)

        btn_s = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                 f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 14px; }}"
                 f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        def _save():
            repo = inp.text().strip()
            # Basic validation — must be "owner/repo" format
            if repo and "/" not in repo:
                QMessageBox.warning(dlg, "Invalid Format",
                    "Please enter the repository in 'owner/repo' format.")
                return
            _save_github_repo(repo)
            self._append_log(
                f"Update repo set to: {repo or '(cleared)'}", "ok"
            )
            dlg.accept()

        save_btn = QPushButton("Save")
        save_btn.setStyleSheet(btn_s)
        save_btn.clicked.connect(_save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(btn_s)
        cancel_btn.clicked.connect(dlg.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        dlg.exec()

    def _check_for_update_manual(self) -> None:
        """Manually trigger an update check against the configured GitHub repo."""
        repo = _GITHUB_REPO or _load_github_repo()
        if not repo:
            reply = QMessageBox.question(
                self, "No Repository Configured",
                "No GitHub repository is configured for update checks.\n\n"
                "Would you like to configure one now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._update_settings()
            return

        self._append_log(f"Checking for updates from github.com/{repo}…", "info")
        try:
            update = check_for_update()
            if update:
                reply = QMessageBox.question(
                    self,
                    f"Update Available — v{update['version']}",
                    f"A newer version of Draugr is available:\n\n"
                    f"  Current:  v{DRAUGR_VERSION}\n"
                    f"  Latest:   v{update['version']}\n\n"
                    f"Would you like to open the release page?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    QDesktopServices.openUrl(
                        __import__("PyQt6.QtCore", fromlist=["QUrl"]).QUrl(update["url"])
                    )
                self._append_log(
                    f"Update available: v{update['version']} — {update['url']}", "warn"
                )
            else:
                QMessageBox.information(
                    self, "Up to Date",
                    f"Draugr v{DRAUGR_VERSION} is the latest version."
                )
                self._append_log(f"✓ Draugr v{DRAUGR_VERSION} is up to date.", "ok")
        except Exception as e:
            QMessageBox.warning(self, "Update Check Failed",
                f"Could not reach GitHub:\n{e}")
            self._append_log(f"Update check failed: {e}", "warn")
    def _manage_tags(self) -> None:
        """
        Assign persistent tags to software names.
        Tags flow into the Tags column of the CSV and can be read
        by plugins (score_modifier, enrich_row) and reports.
        Built-in recognised tags: internet-facing, critical, contractor,
        legacy, ot-connected, test-only, accepted-risk.
        Custom tags are also supported.
        """
        from PyQt6.QtWidgets import QDialog, QTableWidget, QTableWidgetItem

        dlg = QDialog(self)
        dlg.setWindowTitle("Software Tag Manager")
        dlg.setMinimumSize(600, 420)
        dlg.setStyleSheet(f"background:{C.BG}; color:{C.FG};")
        layout = QVBoxLayout(dlg)

        info = QLabel(
            "Assign tags to software items. Tags are matched by name (case-insensitive) "
            "and written to the Tags column of every scan CSV.\n"
            "Recognised tags: internet-facing · critical · contractor · legacy · "
            "ot-connected · test-only · accepted-risk  (custom tags also allowed)"
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{C.FG_DIM}; font-size:11px;")
        layout.addWidget(info)

        table = QTableWidget(0, 2)
        table.setHorizontalHeaderLabels(["Software Name", "Tags (comma-separated)"])
        table.setStyleSheet(
            f"QTableWidget {{ background:{C.BG_CARD}; color:{C.FG}; "
            f"border:1px solid {C.BORDER}; gridline-color:{C.BORDER}; }}"
            f"QHeaderView::section {{ background:{C.BG_INPUT}; color:{C.FG_DIM}; "
            f"border:1px solid {C.BORDER}; padding:4px; }}"
        )
        table.horizontalHeader().setStretchLastSection(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        # Populate from current tags
        for sw_name, tags in sorted(self._tags.items()):
            ri = table.rowCount()
            table.insertRow(ri)
            table.setItem(ri, 0, QTableWidgetItem(sw_name))
            table.setItem(ri, 1, QTableWidgetItem(tags))
        layout.addWidget(table)

        btn_s = (f"QPushButton {{ background:{C.BG_INPUT}; color:{C.FG}; "
                 f"border:1px solid {C.BORDER}; border-radius:4px; padding:6px 12px; }}"
                 f"QPushButton:hover {{ background:{C.BG_HOVER}; }}")
        btn_layout = QHBoxLayout()

        def _add_row():
            ri = table.rowCount()
            table.insertRow(ri)
            table.setItem(ri, 0, QTableWidgetItem(""))
            table.setItem(ri, 1, QTableWidgetItem(""))
            table.editItem(table.item(ri, 0))

        def _delete_row():
            rows = sorted({i.row() for i in table.selectedItems()}, reverse=True)
            for ri in rows:
                table.removeRow(ri)

        def _save():
            self._tags = {}
            for ri in range(table.rowCount()):
                name_item = table.item(ri, 0)
                tags_item = table.item(ri, 1)
                sw_name = (name_item.text() if name_item else "").strip().lower()
                tags    = (tags_item.text() if tags_item else "").strip()
                if sw_name and tags:
                    self._tags[sw_name] = tags
            self._save_tags()
            self._append_log(f"Software tags saved: {len(self._tags)} entries", "ok")
            dlg.accept()

        for label, slot in [("Add Row", _add_row), ("Delete Selected", _delete_row)]:
            btn = QPushButton(label)
            btn.setStyleSheet(btn_s)
            btn.clicked.connect(slot)
            btn_layout.addWidget(btn)

        btn_layout.addStretch()
        save_btn = QPushButton("Save")
        save_btn.setStyleSheet(btn_s)
        save_btn.clicked.connect(_save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(btn_s)
        cancel_btn.clicked.connect(dlg.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        dlg.exec()


# ----------------------------------------------------------------------
# Splash screen
# ----------------------------------------------------------------------
class DraugrSplash(QSplashScreen):
    """
    Cinematic splash screen for Draugr.
    Displays for ~3 seconds then closes and shows the main window.
    If a draugr_splash.png exists next to the script it is used as
    the background; otherwise a fully procedural dark scene is painted.
    """

    DISPLAY_MS = 3000

    def __init__(self):
        pixmap = self._build_pixmap()
        super().__init__(pixmap, Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)

    def _build_pixmap(self) -> QPixmap:
        img_path = Path(__file__).with_name("draugr_splash.png")
        if img_path.exists():
            pm = QPixmap(str(img_path))
            if not pm.isNull():
                scaled = pm.scaled(
                    900, 520,
                    Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                    Qt.TransformationMode.SmoothTransformation,
                )
                return self._overlay_text(scaled)
        return self._paint_procedural()

    def _paint_procedural(self) -> QPixmap:
        W, H = 900, 520
        pm = QPixmap(W, H)
        pm.fill(QColor("#000000"))
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        bg = QLinearGradient(0, 0, 0, H)
        bg.setColorAt(0.0, QColor("#170909"))
        bg.setColorAt(0.4, QColor("#1f0d0d"))
        bg.setColorAt(1.0, QColor("#0d0505"))
        p.fillRect(0, 0, W, H, bg)

        glow = QRadialGradient(W // 2, H // 3, 320)
        glow.setColorAt(0.0, QColor(203, 50, 44, 110))
        glow.setColorAt(0.5, QColor(151, 43, 40, 50))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.fillRect(0, 0, W, H, glow)

        scan_color = QColor(0, 0, 0, 35)
        for y in range(0, H, 3):
            p.fillRect(0, y, W, 1, scan_color)

        self._draw_reaper(p, W, H)

        import random
        rng = random.Random(42)
        p.setPen(QColor(180, 0, 30, 80))
        for _ in range(180):
            x = rng.randint(0, W)
            y = rng.randint(0, H)
            length = rng.randint(6, 28)
            p.drawLine(x, y, x, y + length)

        self._draw_title(p, W, H)
        p.end()
        return pm

    def _draw_reaper(self, p: QPainter, W: int, H: int):
        from PyQt6.QtGui import QPen
        cx = W // 2

        robe = QPainterPath()
        robe.moveTo(cx, H * 0.08)
        robe.lineTo(cx - 180, H * 0.82)
        robe.lineTo(cx + 180, H * 0.82)
        robe.closeSubpath()
        robe_grad = QLinearGradient(cx, H * 0.08, cx, H * 0.82)
        robe_grad.setColorAt(0.0, QColor(30, 0, 5, 220))
        robe_grad.setColorAt(1.0, QColor(5, 0, 2, 180))
        p.fillPath(robe, robe_grad)

        p.setBrush(QColor(15, 0, 5, 230))
        p.setPen(QColor(0, 0, 0, 0))
        p.drawEllipse(cx - 60, int(H * 0.04), 120, 110)

        void_glow = QRadialGradient(cx, H * 0.13, 36)
        void_glow.setColorAt(0.0, QColor(200, 0, 20, 160))
        void_glow.setColorAt(0.6, QColor(100, 0, 10, 60))
        void_glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.fillRect(cx - 50, int(H * 0.06), 100, 80, void_glow)

        staff_pen = QPen(QColor(60, 0, 10, 190))
        staff_pen.setWidth(3)
        p.setPen(staff_pen)
        p.drawLine(cx + 50, int(H * 0.10), cx + 210, int(H * 0.75))

        blade = QPainterPath()
        blade.moveTo(cx + 50, H * 0.10)
        blade.cubicTo(cx + 160, H * 0.0, cx + 260, H * 0.12, cx + 195, H * 0.28)
        blade.cubicTo(cx + 140, H * 0.20, cx + 80, H * 0.18, cx + 50, H * 0.10)
        blade_grad = QLinearGradient(cx + 50, H * 0.05, cx + 260, H * 0.28)
        blade_grad.setColorAt(0.0, QColor(220, 20, 30, 230))
        blade_grad.setColorAt(0.5, QColor(255, 60, 60, 200))
        blade_grad.setColorAt(1.0, QColor(140, 0, 10, 150))
        p.fillPath(blade, blade_grad)

        glow_pen = QPen(QColor(255, 80, 80, 120))
        glow_pen.setWidth(2)
        p.setPen(glow_pen)
        p.drawPath(blade)

        edge_pen = QPen(QColor(140, 0, 20, 60))
        edge_pen.setWidth(1)
        p.setPen(edge_pen)
        p.drawPath(robe)

    def _draw_title(self, p: QPainter, W: int, H: int, draw_draugr: bool = True):
        if draw_draugr:
            font = QFont("Courier New", 54, QFont.Weight.Bold)
            font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 12)
            p.setFont(font)

            p.setPen(QColor(85, 30, 30, 100))
            p.drawText(2, int(H * 0.80) + 2, W - 2, 70,
                       Qt.AlignmentFlag.AlignHCenter, "DRAUGR")

            p.setPen(QColor(203, 50, 44, 255))
            p.drawText(0, int(H * 0.80), W, 70,
                       Qt.AlignmentFlag.AlignHCenter, "DRAUGR")

        sub_font = QFont("Courier New", 16)
        sub_font.setBold(True)
        sub_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 6)
        p.setFont(sub_font)
        p.setPen(QColor(163, 140, 140, 180))
        p.drawText(0, int(H * 0.91), W, 30,
                   Qt.AlignmentFlag.AlignHCenter, "THREAT INTELLIGENCE SYSTEM")

        ver_font = QFont("Courier New", 9)
        p.setFont(ver_font)
        p.setPen(QColor(85, 30, 30, 200))
        p.drawText(0, H - 22, W - 12, 20,
                   Qt.AlignmentFlag.AlignRight, "v2.8.2  //  INTERNAL USE ONLY")

    def _overlay_text(self, pm: QPixmap) -> QPixmap:
        W, H = pm.width(), pm.height()
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        vignette = QLinearGradient(0, H * 0.6, 0, H)
        vignette.setColorAt(0.0, QColor(0, 0, 0, 0))
        vignette.setColorAt(1.0, QColor(0, 0, 0, 200))
        p.fillRect(0, 0, W, H, vignette)

        # Image is present — skip DRAUGR text, subtitle only
        self._draw_title(p, W, H, draw_draugr=False)
        p.end()
        return pm

# ----------------------------------------------------------------------
# Application entry point
# ----------------------------------------------------------------------
# ======================================================================
#  SBOM / multi-host import helpers
# ======================================================================

def parse_sbom_cyclonedx(path: str) -> List[Tuple[str, str, str, str]]:
    """
    Parse a CycloneDX SBOM (JSON format) into (name, version, publisher, "") tuples.
    Supports CycloneDX 1.4 and 1.5 component arrays.
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    entries: List[Tuple[str, str, str, str]] = []
    components = data.get("components", [])
    if not components and "metadata" in data:
        # Some CycloneDX docs nest components under metadata.component
        meta_comp = data.get("metadata", {}).get("component", {})
        if meta_comp:
            components = [meta_comp]

    for comp in components:
        if not isinstance(comp, dict):
            continue
        name      = str(comp.get("name", "") or "").strip()
        version   = str(comp.get("version", "") or "").strip()
        publisher = str(comp.get("publisher", "") or comp.get("group", "") or "").strip()
        if name:
            entries.append((name, version, publisher, ""))
        # Recurse into sub-components
        for sub in comp.get("components", []):
            sub_name    = str(sub.get("name", "") or "").strip()
            sub_version = str(sub.get("version", "") or "").strip()
            sub_pub     = str(sub.get("publisher", "") or "").strip()
            if sub_name:
                entries.append((sub_name, sub_version, sub_pub, ""))

    return entries


def parse_sbom_spdx(path: str) -> List[Tuple[str, str, str, str]]:
    """
    Parse an SPDX SBOM (JSON format, SPDX 2.3) into (name, version, publisher, "") tuples.
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    entries: List[Tuple[str, str, str, str]] = []
    packages = data.get("packages", [])
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name      = str(pkg.get("name", "") or "").strip()
        version   = str(pkg.get("versionInfo", "") or "").strip()
        # SPDX originator field: "Organization: Acme Corp" or "Tool: draugr"
        originator = str(pkg.get("originator", "") or "").strip()
        publisher  = originator.split(":", 1)[1].strip() if ":" in originator else originator
        if name and name != "NOASSERTION":
            entries.append((name, version, publisher, ""))

    return entries


def parse_software_input(path: str) -> List[Tuple[str, str, str, str]]:
    """
    Auto-detect input format and dispatch to the correct parser.
    Supports: CSV/TXT (inventory lists), CycloneDX JSON, SPDX JSON.
    """
    path_lower = path.lower()

    # Try SBOM formats based on extension or content sniff
    if path_lower.endswith(".json"):
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                peek = json.load(f)
            # CycloneDX detection
            if peek.get("bomFormat", "").lower() == "cyclonedx" or "components" in peek:
                return parse_sbom_cyclonedx(path)
            # SPDX detection
            if "SPDX" in str(peek.get("spdxVersion", "")) or "packages" in peek:
                return parse_sbom_spdx(path)
        except (json.JSONDecodeError, KeyError):
            pass

    # Default: CSV / plain-text inventory
    return parse_software_list(path)


def aggregate_multi_host(
    host_files: List[str],
) -> Dict[str, List[Tuple[str, str, str, str]]]:
    """
    Parse multiple inventory files and return a dict mapping
    hostname → list of (name, version, publisher, install_date) tuples.
    Hostname is inferred from the filename stem.
    """
    hosts: Dict[str, List[Tuple[str, str, str, str]]] = {}
    for path in host_files:
        stem     = Path(path).stem
        hostname = re.sub(r"_(software|agent|inventory|scan).*", "", stem, flags=re.IGNORECASE)
        entries  = parse_software_input(path)
        hosts[hostname] = entries
    return hosts


# ======================================================================
#  Headless CLI mode
# ======================================================================

def _run_headless_scan(args: argparse.Namespace) -> int:
    """
    Run a full Draugr scan from the command line without the GUI.
    Returns 0 on success, 1 on failure.
    """
    import traceback

    print(f"[Draugr CLI] Software input: {args.input}")
    print(f"[Draugr CLI] Output dir:     {args.output}")

    # Parse software list
    try:
        if args.multi_host:
            host_map  = aggregate_multi_host(args.input)
            # Flatten with host tag embedded in publisher field for now
            software: List[Tuple[str, str, str, str]] = []
            for host, entries in host_map.items():
                for name, version, publisher, idate in entries:
                    pub = f"{publisher} [{host}]" if publisher else f"[{host}]"
                    software.append((name, version, pub, idate))
            print(f"[Draugr CLI] Multi-host mode: {len(host_map)} hosts, {len(software)} total entries")
        else:
            software = parse_software_input(args.input[0] if isinstance(args.input, list) else args.input)
            print(f"[Draugr CLI] {len(software)} software entries loaded")
    except Exception as e:
        print(f"[Draugr CLI] ERROR parsing input: {e}")
        return 1

    if not software:
        print("[Draugr CLI] No software entries found — check your input file.")
        return 1

    # Setup output paths
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_dir = out_dir / "reports"
    report_dir.mkdir(exist_ok=True)
    log_dir = out_dir / "logs"
    log_dir.mkdir(exist_ok=True)

    stem = Path(args.input[0] if isinstance(args.input, list) else args.input).stem
    csv_path      = report_dir / f"{stem}.csv"
    exec_path     = report_dir / f"{stem}_executive_report.html"
    tech_path     = report_dir / f"{stem}_technical_report.html"
    def_path      = tech_path   # same file
    rt_path       = report_dir / f"{stem}_redteam_report.html"
    scan_log_path = log_dir / f"{stem}_scan.log"
    err_log_path  = log_dir / f"{stem}_error.log"

    # Run scan in this thread (CLI mode — no Qt event loop)
    worker = ScanWorker(
        software=software,
        kev_path=args.kev or "",
        api_key=args.api_key or "",
        output_path=str(csv_path),
        cpe_mapping_path=args.cpe_map or "",
        show_medium=True,
        show_low=True,
        resources_dir=args.resources or "",
        executive_report_path=str(exec_path),
        comp_report_path=str(tech_path),
        defensive_report_path=str(def_path),
        redteam_report_path=str(rt_path),
        error_log_path=str(err_log_path),
        scan_log_path=str(scan_log_path),
        write_logs=True,
        otx_api_key=args.otx_key or "",
    )

    # Connect signals to print output
    worker.log_signal.connect(lambda msg, level: print(f"  [{level.upper():7}] {msg}"))
    worker.status_signal.connect(lambda s: print(f"  [STATUS ] {s}"))
    worker.progress_signal.connect(
        lambda cur, tot: print(f"  [PROG   ] {cur}/{tot}", end="\r")
    )

    finished = [False]
    def _done():
        finished[0] = True
    worker.finished_signal.connect(_done)

    # Run in the current thread (QThread.run() directly)
    try:
        worker.run()
    except Exception as e:
        print(f"\n[Draugr CLI] SCAN ERROR: {e}")
        traceback.print_exc()
        return 1

    # Diff mode
    if args.diff and HAS_DIFF:
        try:
            print(f"\n[Draugr CLI] Computing diff: {args.diff} → {csv_path}")
            old_rows = load_scan_csv(args.diff)
            new_rows = load_scan_csv(str(csv_path))
            diff     = compute_diff(old_rows, new_rows)
            diff_html_path = report_dir / f"{stem}_diff.html"
            diff_csv_path  = report_dir / f"{stem}_diff.csv"
            with open(diff_html_path, "w", encoding="utf-8") as f:
                f.write(build_diff_report(
                    diff,
                    old_label=Path(args.diff).name,
                    new_label=csv_path.name,
                ))
            n_csv = export_diff_csv(diff, str(diff_csv_path))
            stats = diff["stats"]
            print(f"[Draugr CLI] Diff: {stats['new_findings']} new, "
                  f"{stats['resolved']} resolved, {stats['worsened']} worsened, "
                  f"{stats['improved']} improved")
            print(f"[Draugr CLI] Diff report → {diff_html_path}")
        except Exception as e:
            print(f"[Draugr CLI] Diff failed: {e}")

    print(f"\n[Draugr CLI] Scan complete. Outputs in: {out_dir}")
    return 0


def main():
    # ── CLI argument check (headless mode) ────────────────────────────
    # If --scan flag is present, run headless without starting Qt
    if "--scan" in sys.argv or "--help" in sys.argv:
        parser = argparse.ArgumentParser(
            prog="draugr",
            description="Draugr Threat Intelligence System — headless CLI mode",
        )
        parser.add_argument("--scan",      required=True, help="Path to software list / SBOM / CSV")
        parser.add_argument("--output",    required=True, help="Output directory")
        parser.add_argument("--kev",       default="",    help="Path to KEV JSON file (optional)")
        parser.add_argument("--cpe-map",   default="",    dest="cpe_map", help="Path to CPE mappings JSON (optional)")
        parser.add_argument("--api-key",   default="",    dest="api_key", help="NVD API key (optional)")
        parser.add_argument("--otx-key",   default="",    dest="otx_key", help="OTX API key (optional)")
        parser.add_argument("--resources", default="",    help="Path to enrichment DBs folder (optional)")
        parser.add_argument("--diff",      default="",    help="Previous scan CSV to diff against (optional)")
        parser.add_argument("--multi-host",action="store_true", dest="multi_host",
                            help="Treat --scan as glob/list of per-host CSVs and aggregate")
        args = parser.parse_args()
        args.input = args.scan
        sys.exit(_run_headless_scan(args))

    # ── GUI mode ───────────────────────────────────────────────────────
    if requests is None:
        print("ERROR: 'requests' library is required.\n  pip install requests")
        sys.exit(1)
    if not HAS_PYQT6:
        print("ERROR: 'PyQt6' library is required.\n  pip install PyQt6")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Apply theme stylesheet
    if HAS_THEMES:
        app.setStyleSheet(qt_stylesheet())
    else:
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(C.BG))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(C.FG))
        palette.setColor(QPalette.ColorRole.Base, QColor(C.BG_INPUT))
        palette.setColor(QPalette.ColorRole.Text, QColor(C.FG))
        palette.setColor(QPalette.ColorRole.Button, QColor(C.BG_CARD))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(C.FG))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(C.ACCENT))
        app.setPalette(palette)

    # Load plugins on startup
    if HAS_PLUGINS:
        loaded = load_plugins()
        if loaded:
            print(f"[Draugr] {len(loaded)} plugin(s) loaded: {', '.join(p['name'] for p in loaded)}")

    # --- splash screen ---
    splash = DraugrSplash()
    splash.show()
    app.processEvents()

    window = CVEScannerWindow()

    def _launch():
        splash.finish(window)
        window.show()

    QTimer.singleShot(DraugrSplash.DISPLAY_MS, _launch)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
