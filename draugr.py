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
# 6) ATT&CK → NIST 800-53 mapping (offline DB)
# ------------------------------------------------------------------
def map_nist_controls(
    technique_ids: List[str],
    nist_db: Dict[str, Any],
) -> List[str]:
    """Map ATT&CK technique IDs to NIST 800-53 controls using offline DB."""
    if not nist_db:
        return []
    controls: set = set()
    for tid in technique_ids:
        controls.update(nist_db.get(tid, {}).get("nist_controls", []))
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


def parse_software_list(path: str) -> List[Tuple[str, str]]:
    """
    Parse a software list file.
    Supported formats per line:  product  |  product,version
    Lines starting with '#' are ignored.
    """
    entries: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                name, version = [p.strip() for p in line.split(",", 1)]
                if "name" in name.lower():
                    continue
                else:
                    name = name.strip('"')
                    version = version.strip('"')
                    entries.append((name, version))
            else:
                entries.append((line, ""))
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
    ORANGE = "#a3433b"      # high severity — deep burnt orange-red


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
        else:
            lines.append("  - CWE: None mapped")

        if attacks:
            for attack in attacks[:5]:
                lines.append(f"    - ATT&CK: {attack}")
        else:
            lines.append("    - ATT&CK: None mapped")

        if d3f:
            for d in d3f[:5]:
                lines.append(f"      - D3FEND: {d}")
            else:
                lines.append("    - D3FEND: None mapped")

        if nist:
            for n in nist[:5]:
                lines.append(f"      - NIST: {n}")
            else:
                lines.append("    - NIST: None mapped")

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
    logo_path = os.path.join(search_dir, "draugr_logo3.png")
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
        return h.escape(s)

    def inline(s: str) -> str:
        """Apply inline transforms: **bold**, and URL auto-linking."""
        # bold
        s = re.sub(r"\*\*(.+?)\*\*", lambda m: f"<strong>{escape(m.group(1))}</strong>", s)
        # bare URLs → clickable links
        s = re.sub(
            r"(?<![\"'=])(https?://[^\s<>\"']+)",
            lambda m: f'<a href="{m.group(1)}">{m.group(1)}</a>',
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
            out.append(f"<h{level}>{text}</h{level}>")
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


def _wrap_html_report(title: str, body_md: str, logo_b64: str = "", subtitle: str = "") -> str:
    """
    Convert a markdown report body to a fully self-contained HTML document.
    The logo (if provided as a base64 data URI) is embedded in the page header
    alongside the report title.
    """
    escaped_title = html.escape(title)
    logo_tag = '<img src="C:\\Users\\P09816\\OneDrive - NGC\\Desktop\\Coding\\cve_scanner\\draugr_logo.png" alt="Draugr logo">'
    sub_tag = (
        f'<span class="subtitle">{html.escape(subtitle)}</span>'
        if subtitle else ""
    )

    body_html = _markdown_body_to_html(body_md)
     # assemble final page
    full_html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>{escaped_title}</title>
        <style>{_REPORT_CSS}</style>
    </head>
    <body>
    <div class="report-header">{logo_tag}<div class="report-header-text"><h1>{escaped_title}</h1>{sub_tag}</div></div>
    <div class="content">
        {body_html}
    </div>
    </body>
    </html>"""
    return full_html


def build_executive_report_markdown(all_rows: List[Dict[str, Any]], report_title: str = "Draugr Excutive Threat Intelligence Report") -> str:
    """
    Build a markdown executive report grouped by software.
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
        lines.append(f"- Known Exploited Vulnerabilities: {kev_count}")
        lines.append(f"- Public Exploits Available: {exploit_count}")
        lines.append(f"- Highest Risk CVE Score: {max_risk}")
        lines.append(f"- Overall Risk Rating: {overall_risk}")
        lines.append("")

        lines.append("## Threat Map")
        lines.append(_format_threat_map(rows))
        lines.append("")

        lines.append("## Top CVEs by Risk Score")
        lines.append(_format_top_cves(rows, limit=10))
        lines.append("")

        lines.append("## Threat Scenarios")
        lines.append(_format_scenarios(rows, software_name, limit=5))
        lines.append("")

        lines.append("## Mitigations")
        lines.append(_format_mitigations(rows, limit=10))
        lines.append("")
        lines.append("---")
        lines.append("")

    exec_line = "This report groups findings by software and highlights the highest-risk CVEs, mapped threats, likely scenarios, and recommended mitigations."
    exec_md = _executive_summary(all_rows)
    conc_md = _conclusion_section(all_rows)
    body_md = "\n".join(lines).strip() + "\n"
    full_md = f"{exec_line}\n{exec_md}\n{body_md}\n{conc_md}"
    logo_b64 = _load_logo_b64()

    return _wrap_html_report(
        title=report_title,
        body_md=full_md,
        logo_b64=logo_b64,
    )

def build_technical_report_markdown(all_rows: List[Dict[str, Any]], report_title: str = "Draugr Technical Threat Intelligence Report") -> str:
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

        lines.append("## Mitigations")
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
                 error_log_path="", scan_log_path=""):
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
        """Write the accumulated log buffers to their files."""
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
        total = len(self.software)

        for idx, (name, version) in enumerate(self.software, 1):

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

                all_rows.append({
                    "Software Name": name,
                    "Software Version": version,
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

                # Track CVEs with public exploits
                if has_exploit:
                    exploit_cves.append((cid, severity, "; ".join(exploit_sources)))

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
                        "CRITICAL": "error", "HIGH": "warn", "MEDIUM": "info",
                    }.get(rlabel, "dim")
                    self._emit_log(
                        f"    {score:5.1f}  [{rlabel}]  {cid}", color_level,
                    )

            # 2) Public exploits
            if exploit_cves:
                self._emit_log(
                    f"  🔓 {_plural(len(exploit_cves), 'CVE')} with public exploits available",
                    "error",
                )
                for ecid, eseverity, esources in exploit_cves:
                    self._emit_log(
                        f"•   \t{ecid}  [{eseverity}] - ({esources})",
                        "error",
                    )

            # 3) Critical / High severity breakdown
            for sev_label, sev_count, confirmed_list, unverified_list, level in [
                ("CRITICAL", critical_count, c_cves_confirmed, c_cves_unverified, "error"),
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
                    report_title="Draugr Threat Intelligence Executive Report",
                )
                with open(self.executive_report_path, "w", encoding="utf-8") as mdfile:
                    mdfile.write(exec_report_md)
                
                comp_report_md = build_technical_report_markdown(
                    all_rows,
                    report_title="Draugr Threat Intelligence Technical Report",
                )
                with open(self.comp_report_path, "w", encoding="utf-8") as mdfile:
                    mdfile.write(comp_report_md)
                self._emit_log(
                    f"✅ Executive Report written to: {self.executive_report_path}\n✅ Technical Report written to: {self.comp_report_path}",
                    "ok",
                )

            if self.executive_report_path:
                self.status_signal.emit(
                    f"Complete — {len(all_rows)} CVEs across {total} products → "
                    f"{os.path.basename(self.output_path)} + {os.path.basename(self.executive_report_path)} + {os.path.basename(self.comp_report_path)}"

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

        settings_menu.addSeparator()

        self._act_resources = QAction("Enrichment DBs Folder", self)
        self._act_resources.setCheckable(True)
        self._act_resources.setChecked(False)
        self._act_resources.toggled.connect(lambda on: self.resources_row.setVisible(on))
        settings_menu.addAction(self._act_resources)

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

        output_dir = Path(out_path).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)          # <-- creates the folder
        # Use a fixed CSV name inside the folder (you can change it later)
        
        executive_report_path = ""
        comp_report_path = ""
        if generate_executive_report:
            out_base = Path(out_path)
            csv_path = output_dir /str(out_base.with_name(f"{out_base.stem}.csv"))
            executive_report_path = output_dir /str(out_base.with_name(f"{out_base.stem}_executive_report.html"))
            comp_report_path = output_dir /str(out_base.with_name(f"{out_base.stem}_technical_report.html"))
            error_log_path = output_dir /str(out_base.with_name(f"{out_base.stem}_error.log"))
            scan_log_path = output_dir /str(out_base.with_name(f"{out_base.stem}_scan.log"))
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
            scan_log_path=scan_log_path
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
