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
import html
import json
import os
import re
import sys
import time
from collections import defaultdict, Counter
from pathlib import Path
from packaging.version import Version, InvalidVersion
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote_plus
from resources.mitre_attack_scenarios import TECHNIQUE_SCENARIOS as SCENARIOS, get_tactics, get_impact


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
        QAction, QColor, QFont, QLinearGradient, QPainter,
        QPainterPath, QPalette, QPixmap, QRadialGradient,
    )
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
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

# Default path for the CPE mapping override file (same directory as script)
CPE_MAPPING_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpe_mappings.json")


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
    """Robust wrapper around NVD API calls with retry & rate‑limit handling."""
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
            return r.json()
        except Exception as exc:  # pragma: no cover – network failures are hard to test
            if attempt == max_attempts:
                raise RuntimeError(
                    f"Failed NVD request for {url} with params={params!r}: {exc}"
                ) from exc
            time.sleep(min(2 * attempt, 10))
    raise RuntimeError("Unreachable code in nvd_get_json")  # safety


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


def score_cpe_candidate(name: str, version: str, title: str, cpe_name: str) -> int:
    """Heuristic scoring of a CPE entry against the target product."""
    score = 0
    n = normalize_text(name)
    t = normalize_text(title)
    c = normalize_text(cpe_name)

    for token in n.split():
        if token in t or token in c:
            score += 3

    if version_in_text(version, title):
        score += 8
    if version_in_text(version, cpe_name):
        score += 10
    if n in t:
        score += 5
    return score


def search_cpe_candidates(
    name: str,
    version: str,
    max_candidates: int = 5,
    cpe_mappings: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """
    Return the top‑scoring CPE entries for *name*/*version*.

    If *cpe_mappings* contains an override for *name*, use it directly
    instead of querying the NVD CPE dictionary — this is far more precise.
    """
    # --- Check local override first ---
    if cpe_mappings:
        key = normalize_text(name)
        vp = cpe_mappings.get(key)
        if vp:
            # Build a wildcard CPE (version = *) so the CVE search returns
            # all CVEs for that product; version filtering happens later.
            cpe = cpe_name_from_mapping(vp)
            return [{"cpeName": cpe, "title": f"{name} (local mapping)"}]

    # --- Online NVD CPE search (heuristic) ---
    params = {"keywordSearch": name, "resultsPerPage": 100}
    data = nvd_get_json(NVD_CPE_URL, params)
    products = data.get("products", []) or []

    candidates: List[Tuple[int, Dict[str, str]]] = []
    for item in products:
        cpe = item.get("cpe", {}) if isinstance(item, dict) else {}
        cpe_name = cpe.get("cpeName", "")
        title = cpe.get("title", "")
        if not cpe_name:
            continue

        sc = score_cpe_candidate(name, version, title, cpe_name)
        if sc <= 0:
            continue
        candidates.append((sc, {"cpeName": cpe_name, "title": title}))

    candidates.sort(key=lambda x: x[0], reverse=True)

    seen = set()
    best: List[Dict[str, str]] = []
    for _, entry in candidates:
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
) -> List[Dict[str, Any]]:
    """
    High‑level helper used by the UI.
    Returns a de‑duplicated list of CVE dicts for *name*/*version*.
    1) CPE‑based lookup (most precise — uses local mapping if available).
    2) Keyword fallback (covers imperfect CPE mappings).
    ``max_per`` limits total results (0 = no limit).
    """
    seen: set[str] = set()
    results: List[Dict[str, Any]] = []

    for candidate in search_cpe_candidates(name, version, cpe_mappings=cpe_mappings):
        for cve in iter_cves_by_cpe(candidate["cpeName"], kev_index=kev_index):
            cve_id = cve["cve_id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            results.append(cve)
            if 0 < max_per <= len(results):
                return results

    # Skip keyword fallback if we had a precise local mapping
    used_local = bool(cpe_mappings and normalize_text(name) in cpe_mappings)
    if not used_local:
        for cve in iter_cves_by_keyword(name, version, kev_index=kev_index):
            cve_id = cve["cve_id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
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

        if score > 0:
            scores[cve_id] = score

        time.sleep(0.2)   # be polite to free-tier endpoints

    return scores


# ----------------------------------------------------------------------
# Enrichment cache — so CIRCL/GN data gathered in query_otx_for_cves
# can be re-used when formatting the report without a second round-trip.
# ----------------------------------------------------------------------
_THREAT_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}


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
) -> Tuple[float, str]:
    """
    Compute a weighted risk score (0–100) for a single CVE.

    Inputs & weights:
        CVSS base score (0–10)      → 35%  (normalised to 0–100)
        EPSS score (0–1)            → 25%  (normalised to 0–100)
        KEV listed                  → 20%  (binary: 0 or 100)
        Public exploit available    → 10%  (binary: 0 or 100)
        Version confirmed           → 10%  (confirmed=100, unverified=50, N/A=0)

    Returns (score_float, severity_label).
    """
    # --- CVSS component (35%) ---
    cvss_raw = _coerce_float(cve.get("cvss_base_score")) or 0.0
    cvss_norm = (cvss_raw / 10.0) * 100.0

    # --- EPSS component (25%) ---
    epss_raw_str = epss.get("epss_score", "").replace("%", "")
    try:
        epss_pct = float(epss_raw_str)  # already 0–100 from fmt_pct
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
        ver_val = 50.0    # unverified – can't rule out
    else:
        ver_val = 0.0     # confirmed NOT affected

    score = (
        cvss_norm     * 0.35
        + epss_pct    * 0.25
        + kev_val     * 0.20
        + exploit_val * 0.10
        + ver_val     * 0.10
    )
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


def _format_threat_map(rows: List[Dict[str, Any]]) -> str:
    """Build an indented text threat map for one software item."""
    lines: List[str] = []
    for row in rows[:10]:
        cve_id = row.get("CVE ID", "")
        risk = row.get("Risk Score", "")
        risk_level = row.get("Risk Level", "")
        cwes = _split_multi(row.get("CWE", ""))
        attacks = _split_multi(row.get("ATT&CK Techniques", ""))
        d3f = _split_multi(row.get("D3FEND Countermeasures", ""))
        nist = _split_multi(row.get("NIST 800-53 Controls", ""))

        lines.append(f"- {cve_id}  [Risk: {risk} | {risk_level}]")

        if cwes:
            for cwe in cwes[:5]:
                lines.append(f"  - CWE: {cwe}")

        if attacks:
            for attack in attacks[:5]:
                lines.append(f"    - ATT&CK: {attack}")

        if d3f:
            for d in d3f[:5]:
                lines.append(f"      - D3FEND: {d}")

        if nist:
            for n in nist[:5]:
                lines.append(f"      - NIST: {n}")

    return "\n".join(lines) if lines else "- No mapped threats identified."


def _format_top_cves(rows: List[Dict[str, Any]], limit) -> str:
    limit = None if limit == 0 else limit
    lines: List[str] = []
    for row in rows[:limit]:
        cve_id = row.get("CVE ID", "")
        desc = str(row.get("Description", "") or "").strip()
        if not desc:
            desc = "No description available in report row."

        lines.append(f"### {cve_id}")
        lines.append(f"- Risk Score: {row.get('Risk Score', '')} ({row.get('Risk Level', '')})")
        lines.append(f"- CVSS: {row.get('CVSS Base Score', '')} ({row.get('CVSS Severity', '')})")
        lines.append(f"- Description: {desc}")
        lines.append(f"- KEV: {row.get('Known Exploited Vulnerability', 'No')}")
        lines.append(f"- Public Exploit: {row.get('Public Exploit', 'No')}")
        lines.append(f"- EPSS: {row.get('EPSS Score', '')}")
        lines.append(f"- Version Confirmed: {row.get('Version Confirmed', '')}")
        lines.append(f"- Published: {row.get('CVE Date', '')}")
        lines.append(f"- Exploit Sources: {row.get('Exploit Sources', '') or 'None'}")
        lines.append(f"- ATT&CK Techniques: {row.get('ATT&CK Techniques', '') or 'None'}")
        lines.append(f"- D3FEND Countermeasures: {row.get("D3FEND Countermeasures", '') or 'None'}")
        lines.append(f"- NIST 800-53 Controls: {row.get("NIST 800-53 Controls", "") or 'None'}")
        # --- Threat intelligence enrichment from CIRCL / GreyNoise ---
        cve_id = row.get("CVE ID", "")
        if cve_id:
            cached = _THREAT_INTEL_CACHE.get(cve_id, {})
            gn     = cached.get("greynoise", {})
            circl  = cached.get("circl", {})
            if gn.get("noise"):
                lines.append("- GreyNoise: ⚠ Active exploitation traffic observed in the wild")
            elif gn.get("riot"):
                lines.append("- GreyNoise: Known scanner/researcher activity observed")
            capecs = circl.get("capec") or []
            if capecs:
                capec_str = "; ".join(
                    f"CAPEC-{c.get('id','')} {c.get('name','')}" for c in capecs[:3]
                )
                lines.append(f"- Attack Patterns (CAPEC): {capec_str}")
        lines.append(f"- NVD: {row.get('NVD URL', '')}")
        lines.append("")
    return "\n".join(lines).strip()

def _to_list(value):
    """Return a list of non‑empty items from a comma‑separated string.
    Values that are '' , None or '0' are ignored."""
    if not value or str(value).strip() == "0":
        return []
    # split on commas (the original data stores several items separated by commas)
    return [item.strip() for item in str(value).split(",") if item.strip()]

def _format_scenarios(rows: List[Dict[str, Any]], software_name: str, limit) -> str:
    limit = None if limit == 0 else limit
    lines: List[str] = []
    count = 0

    for row in rows:
        attacks = _split_multi(row.get("ATT&CK Techniques", ""))
        if not attacks:
            continue

        first_attack = attacks[0]
        match = re.match(r"^([A-Z0-9.]+)\s*\((.*?)\)$", first_attack)
        if match:
            attack_id, attack_name = match.group(1), match.group(2)
        else:
            attack_id, attack_name = first_attack, first_attack
        
        count += 1      
        cve_id = row.get("CVE ID", "")
                # --- try to get a rich description from the scenario library ------------------------
        scenario_info = SCENARIOS.get(attack_id)
        if scenario_info and scenario_info.get("description"):
            # The library already contains placeholders for {cve_id} and {software_name}
            narrative = scenario_info["description"].format(
                cve_id=cve_id,
                software_name=software_name,
            )
        else:
            # Fallback to the original generic template (the behaviour that existed before)
            narrative = _scenario_template(
                attack_id, attack_name, software_name, cve_id
            )
        tactics_list = get_tactics(attack_id)
        impact_text = get_impact(attack_id)
        d3fend_vals = _to_list(row.get("D3FEND Countermeasures", ""))
        nist_vals = _to_list(row.get("NIST 800-53 Controls", ""))

        lines.append(f"## Scenario {count}: {attack_name}")
        lines.append(f"- CVE: {row.get('CVE ID', '')}")
        lines.append(f"- ATT&CK Technique: {attack_id} ({attack_name})")
        lines.append(f"- Narrative: {narrative}")
        if tactics_list:
            lines.append(f"- Tactics: {', '.join(tactics_list)}")
        if impact_text:
            lines.append(f"- Impact: {impact_text}")
        if len(d3fend_vals) > 0 or len(nist_vals) > 0:
            lines.append("### Primary Mitigations: ")
            if len(d3fend_vals) > 0:
                lines.append("# D3FEND Countermeasures")
                for mit in d3fend_vals:
                    lines.append(f"-   {mit}")
            if len(nist_vals) > 0:
                lines.append("NIST 800-53 Controls")
                for control in nist_vals:
                    lines.append(control)
        else:
            lines.append("- Primary Mitigations: No mapped mitigations or controls")
            
        lines.append("")
        lines.append("="*78)

        if limit is not None and count >= limit:
            break

    return "\n".join(lines).strip() if lines else "No ATT&CK-linked scenarios could be generated."


def _format_mitigations(rows: List[Dict[str, Any]], limit) -> str:
    limit = None if limit == 0 else limit
    d3f_all: List[str] = []
    nist_all: List[str] = []

    for row in rows:
        d3f_all.extend(_split_multi(row.get("D3FEND Countermeasures", "")))
        nist_all.extend(_split_multi(row.get("NIST 800-53 Controls", "")))

    def unique_keep_order(items: List[str]) -> List[str]:
        out = []
        seen = set()
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    d3f_unique = unique_keep_order(d3f_all)[:limit]
    nist_unique = unique_keep_order(nist_all)[:limit]

    lines = ["## Recommended Mitigations", ""]

    lines.append("### D3FEND")
    if d3f_unique:
        lines.extend([f"- {x}" for x in d3f_unique])
    else:
        lines.append("- No D3FEND mappings available")

    lines.append("")
    lines.append("### NIST 800-53")
    if nist_unique:
        lines.extend([f"- {x}" for x in nist_unique])
    else:
        lines.append("- No NIST 800-53 mappings available")

    return "\n".join(lines)

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

def _executive_summary(rows: List[Dict[str, Any]]) -> str:
    """
    Build a **high‑level narrative** that lists:
      • total CVEs, severity distribution, KEV and exploit counts,
      • the top ATT&CK techniques with tactic context,
      • the defend‑mitigations (D3FEND + NIST) that cover the majority of findings.
    """
    # ----- severity totals -------------------------------------------------
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
    kev_total = 0
    exploit_total = 0
    confirmed_total = 0
    max_risk_score = 0.0
    software_set: set = set()

    for r in rows:
        sev = str(r.get("CVSS Severity", "") or r.get("Risk Level", "") or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["OTHER"] += 1

        if str(r.get("Known Exploited Vulnerability", "")).upper() == "YES":
            kev_total += 1
        if str(r.get("Public Exploit", "")).upper() == "YES":
            exploit_total += 1
        if str(r.get("Version Confirmed", "")).upper() == "YES":
            confirmed_total += 1

        try:
            rs = float(r.get("Risk Score", 0))
            if rs > max_risk_score:
                max_risk_score = rs
        except (TypeError, ValueError):
            pass

        sw = str(r.get("Software Name", "")).strip()
        if sw:
            software_set.add(sw)

    total_cves = sum(sev_counts.values())

    # ----- top techniques --------------------------------------------------
    top = _top_techniques(rows, top_n=5)

    # ----- build markdown ---------------------------------------------------
    md = ["## Executive Summary", ""]
    md.append(
        f"The scan identified **{total_cves}** CVEs across "
        f"**{len(software_set)}** software {'items' if len(software_set) != 1 else 'item'}. "
        f"Severity breakdown – Critical: **{sev_counts['CRITICAL']}**, "
        f"High: **{sev_counts['HIGH']}**, Medium: **{sev_counts['MEDIUM']}**, "
        f"Low: **{sev_counts['LOW']}**."
    )
    md.append("")

    # Key risk indicators
    risk_items: List[str] = []
    if kev_total:
        risk_items.append(f"**{kev_total}** {'CVEs are' if kev_total != 1 else 'CVE is'} listed in the CISA Known Exploited Vulnerabilities catalog")
    if exploit_total:
        risk_items.append(f"**{exploit_total}** {'have' if exploit_total != 1 else 'has'} publicly available exploit code")
    if confirmed_total:
        risk_items.append(f"**{confirmed_total}** {'are' if confirmed_total != 1 else 'is'} version‑confirmed against the scanned software")
    if max_risk_score:
        risk_items.append(f"Highest weighted risk score: **{max_risk_score:.1f}**/100")

    if risk_items:
        md.append("Key risk indicators:")
        for item in risk_items:
            md.append(f"- {item}")
        md.append("")

    if top:
        md.append("The most prevalent ATT&CK techniques are:")
        for aid, cnt, meta in top:
            tactics_str = ", ".join(meta.get("tactics", [])) or "—"
            mitig = ", ".join(meta["d3fend"][:3]) or "none"
            if len(meta["d3fend"]) > 3:
                mitig += f" (+{len(meta['d3fend']) - 3} more)"
            nist  = ", ".join(meta["nist"][:3])   or "none"
            if len(meta["nist"]) > 3:
                nist += f" (+{len(meta['nist']) - 3} more)"
            md.append(
                f"- **{meta['name']}** ({aid}) – observed in **{cnt}** CVEs. "
                f"Tactics: {tactics_str}. "
                f"D3FEND mitigations: {mitig}. NIST controls: {nist}."
            )
    else:
        md.append("- No ATT&CK techniques were mapped for the identified CVEs.")

    md.append("")
    md.append(
        "Focusing remediation on the mitigations listed above will address "
        "the majority of the attack surface revealed by this assessment."
    )
    md.append("")
    return "\n".join(md)

def _conclusion_section(rows: List[Dict[str, Any]]) -> str:
    """
    Provide a data-driven step-by-step implementation guide for the
    mitigations surfaced by the scan.
    """
    top = _top_techniques(rows, top_n=5)

    # Gather aggregate stats for the conclusion
    total_cves = len(rows)
    kev_total = sum(1 for r in rows if str(r.get("Known Exploited Vulnerability", "")).upper() == "YES")
    exploit_total = sum(1 for r in rows if str(r.get("Public Exploit", "")).upper() == "YES")
    confirmed_total = sum(1 for r in rows if str(r.get("Version Confirmed", "")).upper() == "YES")
    critical_count = sum(1 for r in rows if str(r.get("CVSS Severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for r in rows if str(r.get("CVSS Severity", "")).upper() == "HIGH")

    # Collect all unique D3FEND and NIST controls across all rows
    all_d3fend: List[str] = []
    all_nist: List[str] = []
    d3_seen: set = set()
    nist_seen: set = set()
    for r in rows:
        for d in _split_multi(r.get("D3FEND Countermeasures", "")):
            if d not in d3_seen:
                d3_seen.add(d)
                all_d3fend.append(d)
        for n in _split_multi(r.get("NIST 800-53 Controls", "")):
            if n not in nist_seen:
                nist_seen.add(n)
                all_nist.append(n)

    md = ["## Conclusion & Implementation Guidance", ""]

    # Situation overview
    md.append(
        f"This assessment identified **{total_cves}** CVEs, of which "
        f"**{critical_count}** are Critical and **{high_count}** are High severity."
    )
    if kev_total or exploit_total:
        parts = []
        if kev_total:
            parts.append(f"**{kev_total}** appear in the CISA KEV catalog")
        if exploit_total:
            parts.append(f"**{exploit_total}** have public exploit code available")
        md.append(f"{'; '.join(parts)}.")
    if confirmed_total:
        md.append(
            f"Of these, **{confirmed_total}** are version-confirmed as affecting "
            f"the scanned software."
        )
    md.append("")

    # Prioritised remediation steps from top techniques
    if top:
        md.append(
            "To address the highest-impact attack vectors, apply the following "
            "actions in priority order:"
        )
        md.append("")

        step = 1
        for aid, cnt, meta in top:
            tname = meta.get("name", aid)
            tactics = ", ".join(meta.get("tactics", [])) or "Unknown"
            md.append(
                f"**Priority {step}: {tname} ({aid})** -- "
                f"affects {cnt} CVE{'s' if cnt != 1 else ''} "
                f"(Tactics: {tactics})"
            )
            if meta["d3fend"]:
                for d in meta["d3fend"][:3]:
                    md.append(f"- Deploy D3FEND counter-measure: **{d}**")
                if len(meta["d3fend"]) > 3:
                    md.append(f"- ... and {len(meta['d3fend']) - 3} additional D3FEND measures")
            if meta["nist"]:
                for n in meta["nist"][:3]:
                    md.append(f"- Enact NIST 800-53 control: **{n}**")
                if len(meta["nist"]) > 3:
                    md.append(f"- ... and {len(meta['nist']) - 3} additional NIST controls")
            if not meta["d3fend"] and not meta["nist"]:
                md.append("- No specific D3FEND or NIST mappings available for this technique")
            md.append("")
            step += 1
    else:
        md.append("No ATT&CK techniques were mapped; remediation should focus on patching the identified CVEs directly.")
        md.append("")

    # Summary totals
    md.append(
        f"Across all findings, **{len(all_d3fend)}** unique D3FEND counter-measures "
        f"and **{len(all_nist)}** unique NIST 800-53 controls were identified."
    )
    md.append("")

    md.append(
        "Implementation roadmap:\n"
        "1. **Prioritise** -- Address KEV-listed and publicly-exploitable CVEs first.\n"
        "2. **Patch** -- Apply vendor patches for all version-confirmed CVEs.\n"
        "3. **Harden** -- Deploy the D3FEND counter-measures and NIST controls listed above.\n"
        "4. **Validate** -- Confirm effectiveness with periodic red-team or ATT&CK-mapping tests.\n"
        "5. **Monitor** -- Continuously scan for new CVEs and update the mitigation set."
    )
    md.append("")
    return "\n".join(md)

# ======================================================================
#  HTML report helpers
# ======================================================================

def _load_logo_b64(script_dir: Optional[str] = None) -> str:
    """
    Return a base64-encoded data URI for draugr_logo.png if it exists
    next to the script, otherwise return an empty string.
    The result can be dropped straight into an <img src="..."> attribute.
    """
    search_dir = script_dir or os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(search_dir, "draugr_logo_small.png")
    if not os.path.isfile(logo_path):
        return ""
    try:
        with open(logo_path, "rb") as fh:
            encoded = base64.b64encode(fh.read()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except Exception:
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
            out.append(f'<h{level} id="{slug}">{text}</h{level}>')
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
    logo_tag = '<img src="C:\\Users\\comro\\Desktop\\Rob\\cyber\\programs\\draugr\\draugr_logo_small.png" alt="Draugr logo">'
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
.toc ol {{
    padding-left: 20px;
    margin: 0;
}}
.toc li {{
    padding: 2px 0;
    list-style: decimal;
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
</style>
    </head>
    <body>
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
    sev_counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in all_rows:
        sev = str(r.get("CVSS Severity", "") or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
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
        "---",
        "",
    ]

    # ── SECTION 3 — MOST CRITICAL RISKS ─────────────────────────────────
    lines += [
        "## Most Critical Risks",
        "",
        "The following systems represent the highest-priority risk to the organization. "
        "Each entry describes the nature of the risk in operational terms.",
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

def build_technical_report_markdown(all_rows: List[Dict[str, Any]], report_title: str = "Technical Threat Intelligence Report") -> str:
    """
    Build a markdown technical report grouped by software.
    Expects the flattened rows created by ScanWorker.
    """
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        key = (str(row.get("Software Name", "")).strip(), str(row.get("Software Version", "")).strip())
        grouped[key].append(row)

    lines: List[str] = [""]

    for (software_name, software_version), rows in sorted(grouped.items(), key=lambda x: x[0][0].lower()):
        rows.sort(key=lambda r: _to_float(r.get("Risk Score", 0)), reverse=True)

        total_cves = len(rows)
        critical = sum(1 for r in rows if str(r.get("CVSS Severity", "")).upper() == "CRITICAL")
        high = sum(1 for r in rows if str(r.get("CVSS Severity", "")).upper() == "HIGH")
        medium = sum(1 for r in rows if str(r.get("CVSS Severity", "")).upper() == "MEDIUM")
        low = sum(1 for r in rows if str(r.get("CVSS Severity", "")).upper() == "LOW")
        kev_count = sum(1 for r in rows if str(r.get("Known Exploited Vulnerability", "")).upper() == "YES")
        exploit_count = sum(1 for r in rows if str(r.get("Public Exploit", "")).upper() == "YES")
        overall_risk = rows[0].get("Risk Level", "INFO")
        max_risk = rows[0].get("Risk Score", 0)

        lines.append(f"# {software_name} {software_version}".strip())
        lines.append("")
        lines.append("## Software Summary")
        lines.append(f"- Total CVEs: {total_cves}")
        lines.append(f"- Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}")
        lines.append(f"- Known Exploited: {kev_count}")
        lines.append(f"- Public Exploits Available: {exploit_count}")
        lines.append(f"- Highest Risk CVE Score: {max_risk}")
        lines.append(f"- Overall Risk Rating: {overall_risk}")
        lines.append("")

        lines.append("## Threat Map")
        lines.append(_format_threat_map(rows))
        lines.append("")

        lines.append("## Top CVEs by Risk Score")
        lines.append(_format_top_cves(rows, limit=0))
        lines.append("")

        lines.append("## Threat Scenarios")
        lines.append(_format_scenarios(rows, software_name, limit=0))
        lines.append("")

        lines.append(_format_mitigations(rows, limit=0))
        lines.append("")
        lines.append("---")
        lines.append("")

    body_md = "\n".join(lines).strip() + "\n"
    exec_md = _executive_summary(all_rows)   # optional top section
    conc_md = _conclusion_section(all_rows)

    full_md = f"{exec_md}\n{body_md}\n{conc_md}"
    logo_b64 = _load_logo_b64()
    return _wrap_html_report(
        title=report_title,
        body_md=full_md,
        logo_b64=logo_b64,
        subtitle="All Vulnerability Findings",
    )
# ======================================================================
#  DEFENSIVE REPORT  – SOC / IT implementation guide
# ======================================================================

# Step-by-step implementation guidance for common D3FEND countermeasures
_D3FEND_IMPL: Dict[str, List[str]] = {
    "Application Hardening": [
        "Audit all installed application versions against the vendor's supported-version matrix.",
        "Apply vendor security patches within the SLA defined in your patch management policy (recommended: Critical ≤ 24 h, High ≤ 72 h).",
        "Enable compiler/linker hardening flags (DEP, ASLR, stack canaries) where vendor build options permit.",
        "Disable unused features, modules, and services within the application.",
        "Review and restrict application file-system and network permissions to the minimum required.",
    ],
    "Network Traffic Filtering": [
        "Review firewall / ACL rules and ensure the affected service is not reachable from untrusted networks.",
        "Implement egress filtering to prevent outbound C2 connections from the affected host.",
        "Deploy or update IDS/IPS signatures for CVEs identified in this scan.",
        "Segment the network so the affected service sits in a dedicated VLAN with limited lateral-movement paths.",
        "Enable logging on all perimeter and internal firewall rules touching the affected service.",
    ],
    "Credential Hardening": [
        "Rotate all service-account and administrative credentials for affected software.",
        "Enforce multi-factor authentication on all privileged accounts that access the affected service.",
        "Audit and remove stale, default, or shared credentials from the affected system.",
        "Implement a privileged access workstation (PAW) policy for administrative access.",
        "Store secrets in a vault solution (e.g., HashiCorp Vault, CyberArk) rather than config files.",
    ],
    "Execution Isolation": [
        "Run the affected service in a dedicated container or VM to limit blast radius.",
        "Apply AppArmor / SELinux mandatory-access-control profiles to the service process.",
        "Restrict script interpreter access (PowerShell, bash, Python) on the host to authorised users only.",
        "Implement application-whitelisting so only signed binaries may execute on the affected host.",
        "Review and tighten OS-level user rights assignments for the service account.",
    ],
    "File Analysis": [
        "Deploy endpoint detection and response (EDR) with memory-scanning and behavioural analysis on the affected host.",
        "Enable file-integrity monitoring (FIM) on directories written to by the affected service.",
        "Configure real-time anti-malware scanning for all paths the service reads from or writes to.",
        "Review recently modified files in service directories for signs of webshells or backdoors.",
        "Set up automated daily hash-comparison of critical application binaries.",
    ],
    "System Call Analysis": [
        "Enable kernel-level audit logging (auditd / Windows Event Forwarding) for the service process.",
        "Deploy a host-based IDS with syscall-level monitoring (e.g., Falco, Sysdig).",
        "Alert on anomalous process-creation chains (e.g., web server spawning cmd.exe or bash).",
        "Review seccomp profiles for containerised workloads and restrict unnecessary syscalls.",
        "Correlate syscall alerts with SIEM to detect exploitation attempts in near-real-time.",
    ],
    "User Behavior Analysis": [
        "Baseline normal login times and source IPs for accounts that access the affected service.",
        "Alert on off-hours or geographically anomalous logins.",
        "Enable UEBA / SIEM correlation rules for privilege escalation patterns.",
        "Audit group-membership changes for privileged groups related to the service.",
        "Implement session recording for all privileged access to the affected system.",
    ],
    "Software Update": [
        "Subscribe to the vendor's security advisory mailing list / RSS feed for the affected product.",
        "Test the latest vendor patch in a staging environment before production deployment.",
        "Deploy the patch using your organisation's change-management process; document rollback steps.",
        "Verify the patched version is active post-deployment (check binary version or package metadata).",
        "Re-run this CVE scan against the patched version to confirm remediation.",
    ],
    "Decoy Environment": [
        "Deploy a honeypot instance of the affected service to detect active exploitation attempts.",
        "Instrument the honeypot with alerting to a SIEM channel monitored 24/7.",
        "Use deception tokens (fake credentials, API keys) in configuration files to detect data theft.",
        "Review honeypot logs weekly for reconnaissance or exploitation traffic patterns.",
    ],
    "Platform Monitoring": [
        "Ensure the affected host forwards all security-relevant events to your SIEM.",
        "Create detection rules for indicators of compromise (IoCs) associated with the CVEs in this report.",
        "Review platform monitoring coverage gaps identified by the MITRE ATT&CK coverage assessment.",
        "Schedule quarterly threat-hunt exercises targeting the ATT&CK techniques in this report.",
        "Integrate CVE threat-intel feeds so new exploit publications auto-create SIEM alerts.",
    ],
}

# Fallback generic steps when a D3FEND term has no specific guidance
_D3FEND_GENERIC = [
    "Review the D3FEND knowledge base at https://d3fend.mitre.org for implementation detail.",
    "Work with your security team to assess applicability and deployment complexity.",
    "Pilot the control in a non-production environment before broad rollout.",
    "Document the control in your security baseline and track compliance.",
]

# Concise implementation notes for NIST SP 800-53 controls relevant to CVEs
_NIST_IMPL: Dict[str, str] = {
    "SI-2":  "Flaw Remediation — establish a patch SLA, track open CVEs in your ITSM tool, and verify remediation.",
    "SI-3":  "Malicious Code Protection — deploy and maintain EDR/AV on all affected hosts; enable real-time scanning.",
    "SI-4":  "System Monitoring — forward host and application logs to SIEM; create detection rules for this CVE set.",
    "SI-5":  "Security Alerts — subscribe to vendor advisories; integrate CVE feeds into your ticketing workflow.",
    "SI-7":  "Software, Firmware, and Information Integrity — enable FIM; verify signatures on software updates.",
    "SI-10": "Information Input Validation — enforce input sanitisation at all entry points exposed by the affected service.",
    "SC-5":  "Denial-of-Service Protection — rate-limit APIs; use a WAF or load-balancer with DDoS mitigation.",
    "SC-7":  "Boundary Protection — review firewall rules; ensure the affected service is not exposed beyond its required boundary.",
    "SC-8":  "Transmission Confidentiality and Integrity — enforce TLS 1.2+ on all connections to the affected service.",
    "SC-28": "Protection of Information at Rest — encrypt sensitive data at rest on the affected host.",
    "AC-3":  "Access Enforcement — enforce least-privilege on all accounts accessing the affected service.",
    "AC-6":  "Least Privilege — audit and trim service-account permissions; remove admin rights where unnecessary.",
    "AC-17": "Remote Access — restrict remote-access paths to the affected service; require MFA.",
    "IA-2":  "Identification and Authentication — enforce MFA for all privileged accounts; disable shared accounts.",
    "IA-5":  "Authenticator Management — rotate credentials; enforce complexity and expiry policies.",
    "AU-2":  "Event Logging — confirm all relevant audit events are enabled and forwarded to your SIEM.",
    "AU-9":  "Protection of Audit Information — restrict write access to audit logs; alert on log tampering.",
    "CM-6":  "Configuration Settings — apply CIS Benchmark hardening for the affected software/OS.",
    "CM-7":  "Least Functionality — disable unused services, ports, and features on the affected host.",
    "CM-8":  "System Component Inventory — update your CMDB to reflect the affected software and current version.",
    "RA-5":  "Vulnerability Monitoring and Scanning — schedule recurring scans against the affected system; track findings in ITSM.",
    "CA-7":  "Continuous Monitoring — integrate this asset into your continuous-monitoring programme.",
    "IR-4":  "Incident Handling — ensure runbooks exist for exploitation of the CVE types found in this scan.",
    "SA-11": "Developer Testing and Evaluation — include CVE regression tests in your CI/CD pipeline for this software.",
}


def _attack_link(tech_id: str, label: str = "") -> str:
    """Return a markdown link to ATT&CK technique page (opens in new tab via inline HTML)."""
    tid = tech_id.replace(".", "/")
    url = f"https://attack.mitre.org/techniques/{tid}/"
    display = label or tech_id
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{html.escape(display)}</a>'


def _d3fend_link(cm_name: str) -> str:
    """Return a markdown-style link to D3FEND technique page."""
    slug = cm_name.replace(" ", "")
    url = f"https://d3fend.mitre.org/technique/d3f:{slug}/"
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{html.escape(cm_name)}</a>'


def _nist_link(ctrl_id: str, label: str = "") -> str:
    """Return a link to NIST SP 800-53 control page."""
    family = ctrl_id.split("-")[0].upper() if "-" in ctrl_id else ctrl_id.upper()
    url = f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={ctrl_id}"
    display = label or ctrl_id
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{html.escape(display)}</a>'


def _nvd_link(cve_id: str) -> str:
    """Return a link to NVD CVE detail page."""
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{html.escape(cve_id)}</a>'


def _defensive_patch_table(rows: List[Dict[str, Any]]) -> str:
    """Build a patch-tracking table: one row per unique software item."""
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        key = (str(r.get("Software Name", "")).strip(), str(r.get("Software Version", "")).strip())
        grouped[key].append(r)

    lines = [
        "| Software | Version | Critical | High | KEV | Public Exploit | Overall Risk | Action |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for (name, ver), sw_rows in sorted(grouped.items(), key=lambda x: x[0][0].lower()):
        crit  = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        high  = sum(1 for r in sw_rows if str(r.get("CVSS Severity","")).upper() == "HIGH")
        kev   = sum(1 for r in sw_rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        expl  = sum(1 for r in sw_rows if str(r.get("Public Exploit","")).upper() == "YES")
        max_rs = max((_to_float(r.get("Risk Score", 0)) for r in sw_rows), default=0.0)
        risk_level = sw_rows[0].get("Risk Level", "INFO") if sw_rows else "INFO"
        action = "PATCH IMMEDIATELY" if (kev or crit) else ("PATCH URGENTLY" if high else "SCHEDULE PATCH")
        lines.append(f"| {name} | {ver} | {crit} | {high} | {kev} | {expl} | {max_rs:.1f} ({risk_level}) | {action} |")
    return "\n".join(lines)


def _defensive_immediate_actions(rows: List[Dict[str, Any]]) -> str:
    """
    List CVEs needing immediate attention: KEV-listed, public exploits, or
    actively observed in the wild via GreyNoise threat intelligence.
    """
    def _is_greynoise_active(cve_id: str) -> bool:
        return _THREAT_INTEL_CACHE.get(cve_id, {}).get("greynoise", {}).get("noise", False)

    urgent = [
        r for r in rows
        if str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
        or str(r.get("Public Exploit","")).upper() == "YES"
        or _is_greynoise_active(r.get("CVE ID",""))
    ]
    urgent.sort(key=lambda r: _to_float(r.get("Risk Score", 0)), reverse=True)

    if not urgent:
        return "No CVEs in this scan are currently listed in the CISA KEV catalog, have confirmed public exploit code, or show active in-the-wild exploitation signals."

    lines: List[str] = []
    for r in urgent[:20]:
        cid   = r.get("CVE ID", "")
        name  = r.get("Software Name", "")
        ver   = r.get("Software Version", "")
        kev   = str(r.get("Known Exploited Vulnerability","")).upper() == "YES"
        expl  = str(r.get("Public Exploit","")).upper() == "YES"
        gn_active = _is_greynoise_active(cid)
        score = r.get("CVSS Base Score", "N/A")
        sev   = r.get("CVSS Severity", "")
        flags = []
        if kev:       flags.append("**KEV-LISTED**")
        if expl:      flags.append("**PUBLIC EXPLOIT**")
        if gn_active: flags.append("**ACTIVE IN-THE-WILD (GreyNoise)**")
        lines.append(f"### {cid}  —  {name} {ver}")
        lines.append(f"- CVSS: {score} ({sev})  |  Flags: {', '.join(flags)}")
        lines.append(f"- Exploit Sources: {r.get('Exploit Sources','') or 'See NVD'}")
        if gn_active:
            lines.append("- GreyNoise: Active exploitation traffic observed — treat as confirmed in-the-wild risk")
        lines.append(f"- NVD: {r.get('NVD URL','')}")
        lines.append("")
        lines.append("**Required actions (complete within 24–72 hours):**")
        lines.append("1. Confirm whether this software version is deployed in production.")
        lines.append("2. Apply the vendor patch — check the NVD link above for vendor advisory.")

        # Build compensating controls block with linked NIST/D3FEND references
        d3fend_vals = _split_multi(r.get("D3FEND Countermeasures", ""))
        nist_vals   = _split_multi(r.get("NIST 800-53 Controls", ""))

        if d3fend_vals or nist_vals:
            comp_parts: List[str] = []
            if d3fend_vals:
                d3_links = ", ".join(
                    f"[{cm}](https://d3fend.mitre.org/technique/d3f:{cm.replace(' ','')}/) (D3FEND)"
                    for cm in d3fend_vals[:3]
                )
                comp_parts.append(f"D3FEND: {d3_links}")
            if nist_vals:
                nist_links = ", ".join(
                    f"[{ctrl.split()[0]}](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={ctrl.split()[0]}) — {ctrl}"
                    for ctrl in nist_vals[:3]
                )
                comp_parts.append(f"NIST 800-53: {nist_links}")
            lines.append(
                f"3. If a patch is unavailable, apply compensating controls: {'; '.join(comp_parts)}."
            )
        else:
            lines.append("3. If a patch is unavailable, apply compensating controls: network isolation, WAF rule, or disable the feature.")

        lines.append("4. Verify remediation by re-scanning or reviewing the patched version string.")
        lines.append("5. File an incident ticket and document the remediation timeline.")
        if kev:
            lines.append("6. CISA BOD 22-01 mandates federal agencies remediate KEV entries — confirm your organisation's compliance deadline.")
        if gn_active and not kev:
            lines.append("6. Although not KEV-listed, GreyNoise confirms active exploitation traffic — escalate priority to match KEV-level urgency.")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines).strip()


def _defensive_control_implementation(rows: List[Dict[str, Any]]) -> str:
    """
    For each unique ATT&CK technique found, produce step-by-step
    implementation guidance covering D3FEND countermeasures and NIST controls.
    All ATT&CK, D3FEND, and NIST references include hyperlinks (open in new tab).
    """
    top = _top_techniques(rows, top_n=10)
    if not top:
        return "No ATT&CK technique mappings were found in this scan. Apply vendor patches and refer to the patch table above."

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

        # D3FEND implementation steps with links
        if d3fend:
            lines.append("### D3FEND Countermeasures — Implementation Steps")
            for cm in d3fend:
                steps = _D3FEND_IMPL.get(cm)
                if not steps:
                    for key, val in _D3FEND_IMPL.items():
                        if key.lower() in cm.lower() or cm.lower() in key.lower():
                            steps = val
                            break
                if not steps:
                    steps = _D3FEND_GENERIC
                d3f_slug = cm.replace(" ", "")
                d3f_url  = f"https://d3fend.mitre.org/technique/d3f:{d3f_slug}/"
                lines.append(f"**{cm}** — [D3FEND reference]({d3f_url})")
                for i, step in enumerate(steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")
        else:
            lines.append("### D3FEND Countermeasures")
            lines.append("- No specific D3FEND mappings available for this technique. Refer to https://d3fend.mitre.org for manual lookup.")
            lines.append("")

        # NIST control implementation notes with links
        if nist:
            lines.append("### NIST SP 800-53 Control Implementation")
            lines.append("| Control | Description | Implementation Note | Reference |")
            lines.append("|---|---|---|---|")
            for ctrl in nist:
                ctrl_id = ctrl.split()[0] if ctrl.split() else ctrl
                note = _NIST_IMPL.get(ctrl_id, "Review NIST SP 800-53 Rev 5 for full implementation guidance.")
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


def _defensive_monitoring_checklist(rows: List[Dict[str, Any]]) -> str:
    """Generate a SOC monitoring and validation checklist."""
    techniques = {t for r in rows for t in _split_multi(r.get("ATT&CK Techniques",""))}
    kev_count  = sum(1 for r in rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
    expl_count = sum(1 for r in rows if str(r.get("Public Exploit","")).upper() == "YES")

    lines = [
        "The following checklist should be completed by the SOC and IT security team after applying the controls above.",
        "",
        "**Patch Verification**",
        "- [ ] All PATCH IMMEDIATELY items in the patch table have been remediated.",
        "- [ ] All PATCH URGENTLY items have been scheduled with a defined completion date.",
        "- [ ] Patched versions have been re-scanned or version strings verified.",
        "- [ ] CMDB / asset inventory updated to reflect new software versions.",
        "",
        "**Detection Engineering**",
        "- [ ] SIEM rules created or updated to detect exploitation of CVEs in this report.",
        "- [ ] IDS/IPS signatures updated with CVE-specific indicators.",
        "- [ ] EDR policies reviewed and exclusions audited for affected host paths.",
    ]

    if kev_count:
        lines += [
            "",
            "**CISA KEV Compliance**",
            f"- [ ] All {kev_count} KEV-listed CVE(s) confirmed remediated.",
            "- [ ] Remediation evidence (ticket number / change record) filed for compliance records.",
            "- [ ] CISA BOD 22-01 deadline confirmed with CISO (federal organisations).",
        ]

    if expl_count:
        lines += [
            "",
            "**Active Exploitation Monitoring**",
            f"- [ ] Threat-hunt exercise completed targeting the {expl_count} CVE(s) with public exploits.",
            "- [ ] Logs reviewed for IoCs associated with the exploit code identified in this report.",
            "- [ ] Incident response runbook updated or created for the exploit scenarios above.",
        ]

    lines += [
        "",
        "**Access & Credential Hygiene**",
        "- [ ] Service-account credentials rotated for all affected software.",
        "- [ ] Privileged-account access audited and excess permissions removed.",
        "- [ ] MFA enforced on all administrative interfaces for affected systems.",
        "",
        "**Ongoing Programme**",
        "- [ ] Next scheduled vulnerability scan date confirmed.",
        "- [ ] Vendor advisory subscription confirmed for all software in this scan.",
        "- [ ] ATT&CK-mapped detection coverage reviewed in your SIEM/SOAR platform.",
        "- [ ] Red-team / purple-team exercise scheduled to validate control effectiveness.",
    ]

    if techniques:
        lines += ["", "**ATT&CK Coverage Validation**"]
        for t in sorted(techniques)[:10]:
            lines.append(f"- [ ] Detection rule validated for: {t}")

    return "\n".join(lines)


# ======================================================================
#  TECHNICAL & DEFENSIVE ENGINEERING REPORT — Supporting data structures
# ======================================================================

# CWE → plain-language technical impact description
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
    "CWE-326":  "Inadequate encryption strength — key length below modern standards (e.g., RSA-1024, ECC-160) vulnerable to factoring or discrete-log attacks.",
    "CWE-319":  "Cleartext transmission — sensitive data transmitted without encryption, interceptable by passive network adversaries.",
    "CWE-200":  "Information exposure — internal state, stack traces, or sensitive data returned to unauthorized parties via error messages or API responses.",
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

# ATT&CK technique ID -> technical detection recommendations
_TECHNIQUE_DETECTION: Dict[str, List[str]] = {
    "T1190": [
        "Monitor web/application server logs for anomalous request patterns: unusually long query strings, encoded payloads (%2F, %00, ../), or unexpected HTTP verbs.",
        "Alert on process creation events where the parent is a web server process (e.g., IIS spawning cmd.exe, Apache spawning /bin/sh).",
        "Deploy WAF rules to detect and block common exploitation patterns (SQLi, XSS, command injection payloads).",
        "Monitor for unexpected outbound connections from application server hosts immediately following inbound exploit attempts.",
    ],
    "T1068": [
        "Enable process creation auditing (Windows Event 4688 / Linux auditd execve) and alert on privilege transitions from standard to SYSTEM/root context.",
        "Monitor for token impersonation API calls (NtCreateToken, ZwDuplicateToken) from non-privileged processes.",
        "Alert on unexpected writes to privileged directories (C:\\Windows\\System32, /etc/sudoers.d) from unprivileged processes.",
        "Deploy kernel exploit mitigations: Credential Guard, SMEP, SMAP, Supervisor Mode Execution Prevention.",
    ],
    "T1059": [
        "Log and alert on suspicious command-line arguments: base64 blobs, -EncodedCommand (PowerShell), IEX, Invoke-Expression, curl|bash patterns.",
        "Enable Script Block Logging (PowerShell) and Module Logging; forward to SIEM.",
        "Alert on unusual parent-child process chains (e.g., Office spawning wscript, web server spawning interpreter).",
        "Restrict interpreter execution via application whitelisting (AppLocker/WDAC on Windows, AppArmor/SELinux on Linux).",
    ],
    "T1203": [
        "Deploy endpoint detection (EDR) with memory-scanning and shellcode detection on all endpoints.",
        "Alert on heap spray indicators: large uniform memory allocations in process heap.",
        "Monitor for ROP chain indicators: unusual ret-after-call patterns in exception records.",
        "Enforce Exploit Protection settings (DEP, ASLR, CFG, SEHOP) on the affected application.",
    ],
    "T1078": [
        "Alert on authentication from unusual source IPs, user-agents, or at anomalous times relative to historical baseline.",
        "Monitor for credential stuffing indicators: high failure-to-success ratio from single IPs across many accounts.",
        "Enable MFA; alert on MFA bypass attempts (push fatigue, SIM swap indicators).",
        "Audit service account activity; alert on service accounts performing interactive logons.",
    ],
    "T1499": [
        "Establish rate-limiting and connection throttling at the network edge for affected service ports.",
        "Monitor for volumetric anomalies: sudden bandwidth spikes, connection-rate outliers from single sources.",
        "Enable SYN cookies on affected hosts; deploy upstream scrubbing for L3/L4 floods.",
        "Alert on application-layer resource exhaustion: thread pool saturation, connection queue overflow events.",
    ],
    "T1005": [
        "Enable file access auditing on sensitive directories; alert on bulk read operations by non-authorized processes.",
        "Monitor for staging indicators: large archive creation (zip, tar, 7z) in temp directories.",
        "Alert on unusual access to credential stores: LSASS memory reads (Windows), /etc/shadow access (Linux), browser credential store access.",
    ],
    "T1557": [
        "Deploy 802.1X port authentication to prevent unauthorized network devices.",
        "Monitor for ARP spoofing: duplicate MAC-to-IP mappings, unexpected ARP replies.",
        "Enable DNSSEC and monitor for DNS response anomalies (unexpected TTL changes, answer substitution).",
        "Enforce mutual TLS (mTLS) on sensitive service-to-service communications.",
    ],
    "T1040": [
        "Monitor for promiscuous-mode NIC flags (ifconfig promisc, ip link show) on host systems.",
        "Alert on unexpected packet capture tools (tcpdump, Wireshark, tshark) executing on non-analyst systems.",
        "Enforce TLS encryption on all inter-service communications to render passive capture ineffective.",
    ],
    "T1110": [
        "Alert on repeated authentication failures from single sources exceeding threshold (e.g., >10 failures in 60 seconds).",
        "Monitor for distributed brute-force: low-and-slow attempts distributed across many source IPs.",
        "Enable account lockout policies; monitor for lockout events as an indicator of brute-force campaigns.",
        "Deploy CAPTCHA or adaptive authentication on externally accessible login endpoints.",
    ],
    "T1548": [
        "Audit UAC bypass events (Windows Event 4673, 4674) and alert on elevation from unexpected contexts.",
        "Monitor sudo command execution on Linux; alert on unusual sudo -l enumeration or unexpected privilege grants.",
        "Alert on setuid/setgid bit modification on Linux executable files.",
    ],
    "T1222": [
        "Enable file and directory permission change auditing (Windows 4670; Linux auditd chmod syscall).",
        "Alert on mass permission change events affecting large numbers of files in short time windows.",
    ],
    "T1552": [
        "Alert on access to known credential storage locations: Windows Credential Manager, SAM hive, LSA secrets, .ssh/ directories.",
        "Monitor for environment variable enumeration (set / env / printenv) from unexpected processes.",
        "Deploy secrets scanning in CI/CD pipelines; alert on commits containing credential patterns.",
    ],
    "T1090": [
        "Monitor for SOCKS proxy establishment from internal hosts to external IPs.",
        "Alert on unusual port-forwarding rules (netsh interface portproxy, ssh -L/-R, rinetd).",
        "Deploy egress filtering to block outbound connections on non-standard ports from application hosts.",
    ],
    "T1189": [
        "Deploy DNS-based threat filtering to block known malicious domains.",
        "Monitor browser process children for unexpected executable launches.",
        "Enable Exploit Protection (EMET-equivalent) for browser processes.",
    ],
}

# ATT&CK technique ID -> actionable technical mitigations
_TECHNIQUE_MITIGATION: Dict[str, List[str]] = {
    "T1190": [
        "Apply the vendor security patch immediately. Verify the patched version is deployed using package metadata or binary version strings.",
        "Implement strict input validation and parameterized queries/prepared statements at the application layer for all external-facing inputs.",
        "Restrict network access to the affected service using host-based firewall rules or network ACLs; limit exposure to required source IPs only.",
        "Deploy a WAF with rule sets targeting the relevant vulnerability class (SQLi, XSS, RCE payloads) as a compensating control pending patch deployment.",
        "Review and revoke any excess permissions held by the service account running the affected component.",
    ],
    "T1068": [
        "Apply the vendor patch. Privilege escalation vulnerabilities typically require local code execution as a prerequisite — patch both the PE vector and any initial access CVEs.",
        "Enforce mandatory integrity controls: run the affected service under a restricted account; apply SELinux/AppArmor profiles on Linux or MIC on Windows.",
        "Enable kernel exploit mitigations: Credential Guard (Windows), SMEP/SMAP (enforced at OS level), Kernel Page Table Isolation.",
        "Audit and reduce service account privileges — apply principle of least privilege; remove local administrator rights from service accounts.",
    ],
    "T1059": [
        "Disable or restrict the relevant interpreter where not operationally required (e.g., PowerShell Constrained Language Mode, shell restrictions via /etc/shells).",
        "Apply application whitelisting (AppLocker/WDAC on Windows) to prevent execution of unauthorized scripts and binaries.",
        "Restrict the affected application's ability to spawn child processes using OS-level controls (seccomp, AppArmor, Windows Job Objects).",
        "Patch the underlying vulnerability that enables the code path to reach the interpreter.",
    ],
    "T1203": [
        "Apply the vendor patch. Client-side exploitation typically targets browser engines, document parsers, or media codecs.",
        "Enable Exploit Protection controls: DEP, ASLR, CFG, and SEHOP on the affected application.",
        "Disable the vulnerable feature or file-type handler if operationally feasible while awaiting patching.",
        "Deploy EDR with memory-resident exploit detection (shellcode scanning, ROP detection) on all endpoints.",
    ],
    "T1078": [
        "Enforce MFA on all external-facing and privileged authentication endpoints.",
        "Rotate all credentials for accounts that may be exposed by the vulnerability; audit recently authenticated sessions for indicators of compromise.",
        "Implement account lockout and alerting for failed authentication patterns.",
        "Review service accounts: disable interactive logon capability; scope to minimum required permissions.",
    ],
    "T1499": [
        "Apply the patch to eliminate the resource exhaustion primitive. As a compensating control, implement rate limiting at the load balancer or reverse proxy.",
        "Deploy the affected service behind a reverse proxy capable of absorbing or shedding malformed requests.",
        "Enable OS-level resource limits (ulimit, cgroups, Windows Job Objects) to prevent single-process resource exhaustion.",
    ],
    "T1005": [
        "Apply the patch. Enforce filesystem ACLs restricting the affected process to the minimum required file-system access.",
        "Implement file integrity monitoring (FIM) on sensitive directories; alert on unexpected bulk reads.",
        "Encrypt sensitive data at rest so that successful file access does not yield usable plaintext.",
    ],
    "T1557": [
        "Enforce TLS with mutual authentication (mTLS) on all inter-service communications.",
        "Deploy certificate pinning for high-value communications channels to prevent certificate substitution attacks.",
        "Enable DNSSEC to protect against DNS-based MitM; monitor for certificate anomalies via Certificate Transparency logs.",
    ],
    "T1040": [
        "Enforce encryption (TLS 1.2+) on all communications channels involving sensitive data.",
        "Audit the network for promiscuous-mode interfaces and unauthorized packet capture tools.",
        "Segment the network to limit the scope of data accessible from any single capture vantage point.",
    ],
    "T1110": [
        "Enforce account lockout after a configurable failure threshold with exponential back-off.",
        "Deploy MFA — credential knowledge alone becomes insufficient for authentication success.",
        "Monitor and alert on authentication failure spikes; block source IPs exceeding brute-force thresholds.",
        "Enforce a strong password policy (minimum 12 characters, complexity requirements, breach-password screening).",
    ],
    "T1548": [
        "Apply the patch that eliminates the privilege escalation path.",
        "Enforce least privilege: revoke local admin rights from standard user accounts; scope service accounts to minimum required permissions.",
        "Enable and tune UAC (Windows) or sudo access controls (Linux) to require explicit user consent for privilege elevation.",
    ],
    "T1222": [
        "Audit and remediate incorrect file/directory permissions; apply the principle of least privilege to ACLs.",
        "Monitor for unauthorized permission changes; implement FIM on critical paths.",
        "Restrict which processes and users can modify permissions via AppArmor/SELinux or WDAC policies.",
    ],
    "T1552": [
        "Remove hard-coded credentials from code; migrate secrets to a vault solution (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).",
        "Rotate all secrets that may have been exposed; revoke compromised API keys and certificates immediately.",
        "Implement automated secrets scanning in the CI/CD pipeline to prevent future credential leakage.",
    ],
    "T1090": [
        "Implement egress filtering at the network boundary; block outbound connections on non-standard ports from application hosts.",
        "Monitor for proxy/tunnel establishment from unexpected processes or hosts.",
        "Apply application-layer controls to restrict which processes may establish outbound network connections.",
    ],
    "T1189": [
        "Apply browser and OS patches. Enforce browser exploit mitigations (sandbox, JIT hardening).",
        "Deploy DNS-based threat filtering to block known exploit kit domains.",
        "Implement Content Security Policy (CSP) headers to reduce XSS and drive-by attack surface.",
    ],
}

# CWE IDs that indicate high-risk architectural patterns requiring design-level remediation
_ARCH_RISK_CWES: Dict[str, str] = {
    "CWE-798": "Hard-coded credentials detected — this is an architectural defect requiring design remediation, not a configuration patch. The binary or source must be refactored to use runtime secret injection.",
    "CWE-319": "Cleartext protocol exposure — any component transmitting sensitive data without encryption represents a persistent architectural risk until the protocol is upgraded.",
    "CWE-295": "Certificate validation bypass — this indicates an intentional or negligent design decision to trust unverified TLS endpoints, rendering encrypted channels equivalent to plaintext.",
    "CWE-306": "Missing authentication — exposed unauthenticated endpoints represent a fundamental access control design gap not addressable by patching alone.",
    "CWE-502": "Deserialization attack surface — use of native deserialization of untrusted data is a high-risk architectural pattern. Consider migration to safer serialization formats (JSON, Protocol Buffers).",
    "CWE-918": "SSRF attack surface — server-side request capabilities without allowlist enforcement expose cloud metadata endpoints, internal services, and SSRF-to-RCE chains.",
    "CWE-611": "XXE attack surface — XML parsers with external entity processing enabled present a persistent SSRF and file-disclosure risk class until parser configuration is hardened globally.",
}


def _cve_chain_analysis(sw_rows: List[Dict[str, Any]]) -> List[str]:
    """
    Identify vulnerability chaining opportunities within a software item.
    Returns a list of chain narrative strings.
    """
    chains: List[str] = []
    cve_by_technique: Dict[str, List[str]] = defaultdict(list)
    has_initial_access = False
    has_privesc        = False
    has_execution      = False
    has_cred_access    = False
    has_lateral        = False

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
            has_initial_access = True
            initial_access_cves.append(cid)
        if "privilege-escalation" in tactics:
            has_privesc = True
            privesc_cves.append(cid)
        if "execution" in tactics:
            has_execution = True
            execution_cves.append(cid)
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
            "SYSTEM/root, granting full host control. This is a high-confidence two-stage attack "
            "path requiring remediation of both CVEs."
        )
    if has_initial_access and has_execution and has_cred_access:
        chains.append(
            f"**Initial Access → Execution → Credential Harvesting:** An attacker gaining execution "
            f"via {initial_access_cves[0] if initial_access_cves else 'an initial-access CVE'} could "
            "leverage execution primitives to deploy credential-harvesting tooling, acquiring credentials "
            "usable for lateral movement beyond the initially compromised host."
        )
    if has_execution and has_lateral:
        chains.append(
            "**Execution → Lateral Movement:** Exploitation of execution-enabling CVEs on this host, "
            "combined with lateral movement attack paths, creates a viable pivot scenario. Attackers "
            "with code execution could enumerate and attack adjacent hosts via harvested credentials "
            "or internal trust relationships."
        )
    high_frequency_techs = [(tid, cves) for tid, cves in cve_by_technique.items() if len(cves) >= 3]
    if high_frequency_techs:
        tid, cves = high_frequency_techs[0]
        chains.append(
            f"**Technique Amplification — {tid}:** {len(cves)} independent CVEs map to this technique, "
            "providing multiple distinct paths to the same attack objective. Patching one CVE does not "
            "close the full attack surface; all must be addressed."
        )
    return chains


def _format_cve_engineering(r: Dict[str, Any], sw_name: str) -> List[str]:
    """
    Format a single CVE into a detailed engineering assessment entry.
    Returns a list of markdown lines.
    """
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
    if sev:        badges.append(f"[{sev}]")
    if kev_f:      badges.append("⚠ KEV")
    if expl_f:     badges.append("🔴 PUBLIC EXPLOIT")
    if gn_active:  badges.append("🟠 ACTIVE IN-WILD")
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
    block.append(f"| Public Exploit Available | {'Yes — ' + (expl_src or 'see NVD') if expl_f else 'No'} |")
    block.append(f"| Version Confirmed | {conf if conf else 'Unverified — based on CPE product match'} |")
    block.append(f"| Published | {pub_date} |")
    # Publisher and patch age from inventory data
    sw_publisher  = str(r.get("Publisher", "") or "")
    sw_idate      = str(r.get("Install Date", "") or "")
    patch_age     = str(r.get("Patch Age (Days)", "") or "")
    if sw_publisher:
        block.append(f"| Publisher | {sw_publisher} |")
    if sw_idate:
        block.append(f"| Install Date | {sw_idate} |")
    if patch_age:
        # Flag if vulnerability was present at install time
        if patch_age == "0 (installed after CVE published)":
            block.append("| Patch Age | Not vulnerable at install — CVE published before install date |")
        else:
            try:
                age_int = int(patch_age)
                age_note = " ⚠ OVERDUE" if age_int > 30 and kev_f else (" ⚠ OVERDUE" if age_int > 90 else "")
                block.append(f"| Patch Age | {patch_age} days since install{age_note} |")
            except ValueError:
                block.append(f"| Patch Age | {patch_age} |")
    if gn_active:
        block.append("| GreyNoise | Active exploitation traffic observed |")
    elif gn_riot:
        block.append("| GreyNoise | Known scanner/research activity observed |")
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
            tech_impact = _CWE_TECHNICAL_IMPACT.get(cwe, "See CWE reference for detailed weakness description.")
            block.append(f"- **[{cwe}]({cwe_url}):** {tech_impact}")
        for cwe in cwes:
            arch_note = _ARCH_RISK_CWES.get(cwe)
            if arch_note:
                block.append(f"- **Architectural Risk ({cwe}):** {arch_note}")
        block.append("")

    block.append("### Exploitability Analysis")
    expl_conditions: List[str] = []
    if vector:
        v = vector.upper()
        if "AV:N" in v:
            expl_conditions.append("**Attack Vector: Network** — exploitable remotely without requiring physical or adjacent network access")
        elif "AV:A" in v:
            expl_conditions.append("**Attack Vector: Adjacent** — requires attacker to be on the same network segment (LAN/VLAN)")
        elif "AV:L" in v:
            expl_conditions.append("**Attack Vector: Local** — requires local code execution as a prerequisite; typically chained after initial access")
        elif "AV:P" in v:
            expl_conditions.append("**Attack Vector: Physical** — requires physical access to the target system")
        if "PR:N" in v:
            expl_conditions.append("**Privileges Required: None** — no prior authentication or authorization required")
        elif "PR:L" in v:
            expl_conditions.append("**Privileges Required: Low** — requires low-privilege authenticated access")
        elif "PR:H" in v:
            expl_conditions.append("**Privileges Required: High** — requires administrative or root-level access as a prerequisite")
        if "UI:N" in v:
            expl_conditions.append("**User Interaction: None** — exploitation does not require victim action; enables autonomous/worm-like propagation")
        elif "UI:R" in v:
            expl_conditions.append("**User Interaction: Required** — victim must perform an action (open file, visit URL)")
        if "AC:L" in v:
            expl_conditions.append("**Attack Complexity: Low** — no special conditions required; exploitation is straightforward and repeatable")
        elif "AC:H" in v:
            expl_conditions.append("**Attack Complexity: High** — exploitation requires race conditions, specific configurations, or adversary-controlled environment elements")
        if "S:C" in v:
            expl_conditions.append("**Scope: Changed** — successful exploitation can affect components beyond the vulnerable component boundary (container escape, hypervisor escape)")
    if expl_f:
        expl_conditions.append(f"**Public Exploit Code Exists** — weaponized PoC or working exploit available: {expl_src or 'check NVD references and Vulners'}. Exploitation barrier is low.")
    if kev_f:
        expl_conditions.append("**CISA KEV Confirmed** — this vulnerability has been weaponized and is actively exploited by threat actors in real-world campaigns.")
    if gn_active:
        expl_conditions.append("**GreyNoise Active Signal** — exploitation or scanning attempts observed against this CVE in the wild.")
    try:
        epss_val = float(str(epss).rstrip("%"))
        if epss_val >= 10.0:
            expl_conditions.append(f"**High EPSS ({epss})** — top-decile exploitation probability; adversary tooling likely exists or is in active development.")
        elif epss_val >= 1.0:
            expl_conditions.append(f"**Moderate EPSS ({epss})** — meaningful exploitation probability within a 30-day window.")
    except (ValueError, TypeError):
        pass

    for ec in expl_conditions:
        block.append(f"- {ec}")
    if not expl_conditions:
        block.append("- Exploitability conditions could not be fully determined — consult the NVD advisory for CVSS vector detail.")
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
        op_impacts.append("Potential for complete compromise of the affected host or service; recovery may require system rebuild.")
    if kev_f or gn_active:
        op_impacts.append("Active exploitation confirmed or observed — incident response posture should be elevated; treat as a potential active incident until cleared.")
    if expl_f:
        op_impacts.append("Public exploit availability reduces the technical barrier for low-skilled threat actors; probability of exploitation is elevated above CVSS score alone.")
    if conf.upper() == "YES":
        op_impacts.append("Version-confirmed as applicable to the specific deployed version — confirmed exposure, not a speculative CPE match.")
    elif not conf:
        op_impacts.append("Version confirmation is pending — manual validation against the exact deployed build is recommended.")
    for oip in op_impacts:
        block.append(f"- {oip}")
    if not op_impacts:
        block.append("- Assess operational impact based on the function and network exposure of the affected component in your environment.")
    block.append("")

    block.append("### Detection Recommendations")
    first_aid = ""
    if attacks:
        m3 = re.match(r"^([A-Z0-9.]+)", attacks[0])
        if m3:
            first_aid = m3.group(1)
    det_recs = _TECHNIQUE_DETECTION.get(first_aid, [])
    cwe_det: List[str] = []
    for cwe in cwes:
        if cwe == "CWE-89":
            cwe_det.append("Monitor application logs for anomalous SQL syntax in query parameters; enable WAF SQL injection rule sets.")
        elif cwe == "CWE-79":
            cwe_det.append("Monitor for script injection payloads in web request parameters; enforce CSP headers.")
        elif cwe == "CWE-798":
            cwe_det.append("Alert on authentication using credentials extracted from code repositories or binary analysis.")
        elif cwe == "CWE-502":
            cwe_det.append("Alert on Java/Python deserialization operations from externally-sourced data; monitor for deserialization gadget chain indicators.")
    for d in (det_recs + cwe_det)[:5]:
        block.append(f"- {d}")
    if not det_recs and not cwe_det:
        block.append("- Review the NVD advisory and vendor security bulletin for CVE-specific indicators of exploitation.")
        block.append("- Enable verbose logging on the affected service and forward to SIEM for anomaly detection.")
    block.append("")

    block.append("### Mitigation Recommendations")
    first_aid2 = ""
    if attacks:
        m4 = re.match(r"^([A-Z0-9.]+)", attacks[0])
        if m4:
            first_aid2 = m4.group(1)
    mit_recs = _TECHNIQUE_MITIGATION.get(first_aid2, [])
    block.append(f"1. **Apply vendor patch** — consult the [NVD advisory]({nvd_url}) for vendor patch details. This is the primary remediation.")
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
    sev_counts    = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    kev_total     = 0
    expl_total    = 0
    confirmed_total = 0
    max_risk      = 0.0
    epss_values: List[float] = []

    for r in all_rows:
        sev = str(r.get("CVSS Severity", "") or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
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
        '<h2>Contents</h2><ol>'
        '<li><a href="#1-executive-technical-summary">1. Executive Technical Summary</a></li>'
        '<li><a href="#2-asset-and-system-overview">2. Asset and System Overview</a></li>'
        '<li><a href="#3-severity-distribution-and-risk-scoring">3. Severity Distribution and Risk Scoring</a></li>'
        '<li><a href="#4-vulnerability-chaining-and-attack-path-analysis">4. Vulnerability Chaining and Attack Path Analysis</a></li>'
        '<li><a href="#5-detailed-cve-analysis">5. Detailed CVE Analysis</a>'
        f'<ol>{sw_toc_items}</ol></li>'
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
        '</ol>'
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

    # Patch age analysis
    import datetime as _dt
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
            lines.append(f"- Exploit Sources: {src}")
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
        lines.append(f"| {cid} | {name} | {ver} | {cvss} | {epss} | {kev} | {src} | {rs} | {conf} |")
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
        '<h2>Contents</h2><ol>'
        '<li><a href="#section-1-engagement-recommendations">Section 1 — Engagement Recommendations</a></li>'
        '<li><a href="#section-2-target-priority-ranking">Section 2 — Target Priority Ranking</a></li>'
        '<li><a href="#section-3-per-target-attack-profiles">Section 3 — Per-Target Attack Profiles</a></li>'
        '<li><a href="#section-4-exploit-inventory">Section 4 — Exploit Inventory</a></li>'
        '<li><a href="#section-5-threat-intelligence-summary">Section 5 — Threat Intelligence Summary</a></li>'
        '<li><a href="#section-6-highest-epss-probability-cves">Section 6 — Highest EPSS Probability CVEs</a></li>'
        '</ol>'
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
                 defensive_report_path="", redteam_report_path="", otx_api_key=""):
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
        self._scan_log_lines:  List[str] = []
        self._error_log_lines: List[str] = []

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

        for idx, (name, version, publisher, install_date) in enumerate(self.software, 1):

            if self.isInterruptionRequested():
                self._emit_log("Scan cancelled by user", "warning")
                self.status_signal.emit("Cancelled by user")
                break

            label = f"{name} {version}".strip()
            self._emit_log(f"[{idx}/{total}] Querying NVD for: {label}", "info")
            self.status_signal.emit(f"Scanning: {idx} of {total} — {label}")
            self.progress_signal.emit(idx - 1, total)  # show progress before work starts

            # -----------------------------------------------------------------
            # Retrieve CVEs
            # -----------------------------------------------------------------
            cves = find_cves_for_software(
                name, version, kev_index=kev_index, cpe_mappings=cpe_mappings,
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

                # ---- risk score ----
                risk_score, risk_label = compute_risk_score(
                    cve, epss, affected, has_exploit,
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
                        import datetime as _dt
                        idate_obj = _dt.datetime.strptime(install_date, "%Y-%m-%d").date()
                        pub_raw   = str(cve.get("published", "") or "")[:10]
                        if pub_raw:
                            cve_date_obj = _dt.datetime.strptime(pub_raw, "%Y-%m-%d").date()
                            if idate_obj >= cve_date_obj:
                                # Installed after CVE published — not vulnerable at install time
                                patch_age_days = "0 (installed after CVE published)"
                            else:
                                delta = (_dt.date.today() - idate_obj).days
                                patch_age_days = str(delta)
                    except (ValueError, TypeError):
                        patch_age_days = ""

                all_rows.append({
                    "Software Name": name,
                    "Software Version": version,
                    "Publisher": publisher,
                    "Install Date": install_date,
                    "Patch Age (Days)": patch_age_days,
                    "CVE ID": cid,
                    "Description": cve.get("description", ""),
                    "CVE Date": cve.get("published", ""),
                    "CVSS Version": cve.get("cvss_version", ""),
                    "CVSS Base Score": cve.get("cvss_base_score", ""),
                    "CVSS Severity": cve.get("cvss_severity", ""),
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
                    "D3FEND Countermeasures": d3fend_str,
                    "NIST 800-53 Controls": nist_str,
                    "NVD URL": nvd_url,
                })

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
            self.progress_signal.emit(idx, total)  # mark this item complete

        # Final progress — ensure bar shows 100%
        self.progress_signal.emit(total, total)

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
            "CVE ID",
            "Description",
            "Risk Score",
            "Risk Level",
            "CVE Date",
            "CVSS Version",
            "CVSS Base Score",
            "CVSS Severity",
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
            "D3FEND Countermeasures",
            "NIST 800-53 Controls",
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
                
                comp_report_md = build_technical_report_markdown(
                    all_rows,
                    report_title="Technical Threat Intelligence Report",
                )
                with open(self.comp_report_path, "w", encoding="utf-8") as mdfile:
                    mdfile.write(comp_report_md)

                if self.defensive_report_path:
                    defensive_html = build_defensive_report(
                        all_rows,
                        report_title="Defensive Implementation Report",
                    )
                    with open(self.defensive_report_path, "w", encoding="utf-8") as f:
                        f.write(defensive_html)

                if self.redteam_report_path:
                    redteam_html = build_redteam_report(
                        all_rows,
                        report_title="Red Team Target Report",
                        otx_results=otx_intel_results,
                    )
                    with open(self.redteam_report_path, "w", encoding="utf-8") as f:
                        f.write(redteam_html)

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
        self.setWindowTitle("Draugr — Threat Intelligence System")
        self.setMinimumSize(860, 760)
        self.resize(920, 820)
        self.scanning = False
        self.worker = None
        self.logging = False
        self._build_ui()

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
        btn_row.addStretch()

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

        btn_row.addWidget(self.scan_btn)
        btn_row.addSpacing(5)
        btn_row.addWidget(self.stop_btn)
        self.scan_btn.clicked.connect(lambda: self._start_scan(generate_executive_report=True))
        self.stop_btn.clicked.connect(self._stop_scan)
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

        # 2) Connect signals to keep the worker in sync
        self.chk_medium.stateChanged.connect(self._update_show_medium)
        self.chk_low.stateChanged.connect(self._update_show_low)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet(
            f"""
            QTextEdit {{
                background: {C.BG_CARD};
                color: {C.FG};
                border: 1px solid {C.BORDER};
                border-radius: 10px;
                padding: 12px;
                font-family: 'Consolas', 'SF Mono', 'Menlo', monospace;
                font-size: 12px;
                selection-background-color: {C.ACCENT};
            }}
            """
        )
        root.addWidget(self.log, 1)

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
        self.scan_btn.setText("▶   Start Scan")
        self.worker._write_logs()
        # Keep the final status from the worker (Complete / Error / Cancelled)
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
        comp_report_path = ""
        defensive_report_path = ""
        redteam_report_path = ""
        error_log_path = ""
        scan_log_path = ""
        if generate_executive_report:
            out_base = Path(out_path)
            csv_path = report_dir /str(out_base.with_name(f"{out_base.stem}.csv"))
            executive_report_path = report_dir /str(out_base.with_name(f"{out_base.stem}_executive_report.html"))
            comp_report_path = report_dir /str(out_base.with_name(f"{out_base.stem}_technical_report.html"))
            defensive_report_path = report_dir /str(out_base.with_name(f"{out_base.stem}_defensive_report.html"))
            redteam_report_path = report_dir /str(out_base.with_name(f"{out_base.stem}_redteam_report.html"))
            if write_logs:
                error_log_path = log_dir /str(out_base.with_name(f"{out_base.stem}_error.log"))
                scan_log_path = log_dir /str(out_base.with_name(f"{out_base.stem}_scan.log"))
        try:
            software = parse_software_list(sw_path)
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Failed to parse software list:\n{exc}")
            return
        if not software:
            QMessageBox.warning(self, "Warning", "Software list is empty.")
            return

        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
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
        )
        self.worker.log_signal.connect(self._append_log) 
        self.worker.progress_signal.connect(self._update_progress)
        self.worker.status_signal.connect(self._update_status)
        self.worker.finished_signal.connect(self._scan_finished)
        self.worker.start()

    def _stop_scan(self):
        if self.worker:
            self._append_log("Stop requested ...", "info")
            self.worker.requestInterruption()
            self.stop_btn.setEnabled(False)



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
def main():
    if requests is None:
        print("ERROR: 'requests' library is required.\n  pip install requests")
        sys.exit(1)
    if not HAS_PYQT6:
        print("ERROR: 'PyQt6' library is required.\n  pip install PyQt6")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(C.BG))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(C.FG))
    palette.setColor(QPalette.ColorRole.Base, QColor(C.BG_INPUT))
    palette.setColor(QPalette.ColorRole.Text, QColor(C.FG))
    palette.setColor(QPalette.ColorRole.Button, QColor(C.BG_CARD))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(C.FG))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(C.ACCENT))
    app.setPalette(palette)

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
