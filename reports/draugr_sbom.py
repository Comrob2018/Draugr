"""
draugr_sbom.py — SBOM generation from Draugr scan results.

Produces CycloneDX 1.5 JSON SBOMs from completed scan rows,
including component metadata, vulnerability annotations, and
CVSS/EPSS scores where available.
"""
import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional


_CYCLONEDX_VERSION = "1.5"
_SPEC_VERSION      = "https://cyclonedx.org/schema/bom-1.5.schema.json"


def _component_type(sw_name: str) -> str:
    """Heuristic: classify component type from name."""
    name_l = sw_name.lower()
    if any(k in name_l for k in ("sdk", "runtime", "framework", ".net", "jdk", "jre")):
        return "framework"
    if any(k in name_l for k in ("library", "lib", "dll")):
        return "library"
    if any(k in name_l for k in ("driver", "firmware")):
        return "firmware"
    if any(k in name_l for k in ("plugin", "extension", "add-in", "add-on")):
        return "library"
    return "application"


def _cpe_from_row(row: Dict[str, Any]) -> Optional[str]:
    """Try to extract a CPE string from the CVE/row data."""
    # Not stored directly in rows but we can reconstruct a rough one
    name = str(row.get("Software Name", "") or "").strip()
    ver  = str(row.get("Software Version", "") or "").strip()
    pub  = str(row.get("Publisher", "") or "").strip()
    if not name:
        return None
    vendor  = re.sub(r"[^a-z0-9]", "_", pub.lower().split()[0]) if pub.split() else "unknown"
    product = re.sub(r"[^a-z0-9]", "_", name.lower().split()[0]) if name.split() else "unknown"
    version = ver or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def generate_cyclonedx(
    rows: List[Dict[str, Any]],
    system_name: str = "Scanned System",
    tool_version: str = "1.0",
) -> Dict[str, Any]:
    """
    Generate a CycloneDX 1.5 BOM dict from Draugr scan rows.
    Returns a dict suitable for json.dumps().
    """
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Group rows by software item
    components_map: Dict[str, Dict[str, Any]] = {}
    vulns_by_sw: Dict[str, List[Dict[str, Any]]] = {}

    for row in rows:
        sw_name = str(row.get("Software Name", "") or "").strip()
        sw_ver  = str(row.get("Software Version", "") or "").strip()
        pub     = str(row.get("Publisher", "") or "").strip()
        idate   = str(row.get("Install Date", "") or "").strip()
        key     = f"{sw_name}||{sw_ver}"

        if key not in components_map:
            bom_ref = hashlib.md5(key.encode()).hexdigest()[:12]
            comp: Dict[str, Any] = {
                "type":        _component_type(sw_name),
                "bom-ref":     bom_ref,
                "name":        sw_name,
                "version":     sw_ver,
            }
            if pub:
                comp["publisher"] = pub
            cpe = _cpe_from_row(row)
            if cpe:
                comp["cpe"] = cpe
            if idate:
                comp["properties"] = [
                    {"name": "draugr:install-date", "value": idate}
                ]
            components_map[key] = comp
            vulns_by_sw[key] = []

        # Build vulnerability entry
        cve_id = str(row.get("CVE ID", "") or "").strip()
        if not cve_id:
            continue

        cvss_score = row.get("CVSS Base Score", "")
        cvss_sev   = str(row.get("CVSS Severity", "") or "").upper()
        epss       = str(row.get("EPSS Score", "") or "").strip()
        kev        = str(row.get("Known Exploited Vulnerability", "")).upper() == "YES"
        nvd_url    = row.get("NVD URL", "") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        desc       = str(row.get("Description", "") or "").strip()[:500]
        risk_score = str(row.get("Risk Score", "") or "")
        cwes       = [c.strip() for c in str(row.get("CWE","") or "").split(";") if c.strip()]

        vuln: Dict[str, Any] = {
            "bom-ref": f"{cve_id}-{components_map[key]['bom-ref']}",
            "id":      cve_id,
            "source":  {"name": "NVD", "url": nvd_url},
        }

        if desc:
            vuln["description"] = desc

        # Ratings
        ratings = []
        if cvss_score:
            sev_map = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"info"}
            rating: Dict[str, Any] = {
                "source": {"name": "NVD"},
                "score":  float(cvss_score),
                "severity": sev_map.get(cvss_sev, "unknown"),
            }
            vector = str(row.get("CVSS Vector","") or "").strip()
            if vector:
                rating["vector"] = vector
            ratings.append(rating)
        if epss:
            try:
                ratings.append({
                    "source":   {"name": "FIRST EPSS"},
                    "score":    float(epss.rstrip("%")),
                    "method":   "EPSS",
                })
            except ValueError:
                pass
        if ratings:
            vuln["ratings"] = ratings

        # CWEs
        if cwes:
            vuln["cwes"] = []
            for cwe in cwes[:5]:
                try:
                    vuln["cwes"].append(int(cwe.replace("CWE-","")))
                except ValueError:
                    pass

        # Properties
        props = []
        if kev:
            props.append({"name": "draugr:kev-listed", "value": "true"})
        if risk_score:
            props.append({"name": "draugr:risk-score", "value": str(risk_score)})
        expl = str(row.get("Public Exploit","") or "")
        if expl.upper() == "YES":
            props.append({"name": "draugr:public-exploit", "value": "true"})
            src = str(row.get("Exploit Sources","") or "").strip()
            if src:
                props.append({"name": "draugr:exploit-sources", "value": src})
        adv_url = str(row.get("Vendor Advisory URL","") or "").strip()
        if adv_url:
            props.append({"name": "draugr:vendor-advisory", "value": adv_url})
        if props:
            vuln["properties"] = props

        # Affects
        vuln["affects"] = [{"ref": components_map[key]["bom-ref"]}]

        # Analysis (recommended state based on KEV/version confirmed)
        conf = str(row.get("Version Confirmed","") or "")
        state = "exploitable" if kev else ("in_triage" if conf == "Unverified" else "affected")
        vuln["analysis"] = {
            "state":     state,
            "justification": "exploitable" if kev else "code_not_present" if conf == "No" else "requires_environment",
        }

        vulns_by_sw[key].append(vuln)

    # Deduplicate vulnerabilities (same CVE can appear for multiple components)
    all_vulns: List[Dict[str, Any]] = []
    seen_vuln_ids: set = set()
    for key, vulns in vulns_by_sw.items():
        for v in vulns:
            vid = v["id"]
            if vid not in seen_vuln_ids:
                seen_vuln_ids.add(vid)
                all_vulns.append(v)

    bom: Dict[str, Any] = {
        "bomFormat":    "CycloneDX",
        "specVersion":  _CYCLONEDX_VERSION,
        "serialNumber": f"urn:uuid:{hashlib.md5(system_name.encode()).hexdigest()}",
        "version":      1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor":  "Draugr",
                    "name":    "Draugr Threat Intelligence System",
                    "version": tool_version,
                }
            ],
            "component": {
                "type":    "device",
                "name":    system_name,
                "version": "1.0",
            },
        },
        "components":     list(components_map.values()),
        "vulnerabilities": all_vulns,
    }
    return bom


def export_sbom(
    rows: List[Dict[str, Any]],
    output_path: str,
    system_name: str = "Scanned System",
    tool_version: str = "1.0",
) -> int:
    """
    Write a CycloneDX 1.5 SBOM to the given path.
    Returns the number of components written.
    """
    bom = generate_cyclonedx(rows, system_name, tool_version)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2)
    return len(bom["components"])
