"""
draugr_advisories.py — Vendor security advisory URL resolution.

Given a publisher name and/or software name, returns the direct vendor
advisory/patch URL when available, supplementing the NVD reference links.
"""
from typing import Dict, List, Optional


# ------------------------------------------------------------------
# Publisher → advisory base URL / search pattern
# ------------------------------------------------------------------
_PUBLISHER_ADVISORY: Dict[str, Dict[str, str]] = {
    # Microsoft
    "microsoft corporation": {
        "name": "Microsoft Security Update Guide",
        "base": "https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
        "search": "https://msrc.microsoft.com/update-guide/",
    },
    "microsoft": {
        "name": "Microsoft Security Update Guide",
        "base": "https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
        "search": "https://msrc.microsoft.com/update-guide/",
    },
    # Adobe
    "adobe": {
        "name": "Adobe Security Bulletins",
        "base": "https://helpx.adobe.com/security/products/",
        "search": "https://helpx.adobe.com/security/security-bulletin.html",
    },
    "adobe systems incorporated": {
        "name": "Adobe Security Bulletins",
        "base": "https://helpx.adobe.com/security/products/",
        "search": "https://helpx.adobe.com/security/security-bulletin.html",
    },
    # Mozilla
    "mozilla corporation": {
        "name": "Mozilla Security Advisories",
        "base": "https://www.mozilla.org/en-US/security/advisories/",
        "search": "https://www.mozilla.org/en-US/security/advisories/",
    },
    "mozilla foundation": {
        "name": "Mozilla Security Advisories",
        "base": "https://www.mozilla.org/en-US/security/advisories/",
        "search": "https://www.mozilla.org/en-US/security/advisories/",
    },
    # Google
    "google llc": {
        "name": "Google Chrome Releases",
        "base": "https://chromereleases.googleblog.com/",
        "search": "https://chromereleases.googleblog.com/",
    },
    "google": {
        "name": "Google Security Blog",
        "base": "https://security.googleblog.com/",
        "search": "https://security.googleblog.com/",
    },
    # Apple
    "apple inc.": {
        "name": "Apple Security Updates",
        "base": "https://support.apple.com/en-us/HT201222",
        "search": "https://support.apple.com/en-us/HT201222",
    },
    "apple": {
        "name": "Apple Security Updates",
        "base": "https://support.apple.com/en-us/HT201222",
        "search": "https://support.apple.com/en-us/HT201222",
    },
    # Oracle
    "oracle corporation": {
        "name": "Oracle Critical Patch Update",
        "base": "https://www.oracle.com/security-alerts/",
        "search": "https://www.oracle.com/security-alerts/",
    },
    "oracle": {
        "name": "Oracle Critical Patch Update",
        "base": "https://www.oracle.com/security-alerts/",
        "search": "https://www.oracle.com/security-alerts/",
    },
    # Cisco
    "cisco systems, inc.": {
        "name": "Cisco Security Advisories",
        "base": "https://tools.cisco.com/security/center/publicationListing.x",
        "search": "https://tools.cisco.com/security/center/publicationListing.x",
    },
    "cisco": {
        "name": "Cisco Security Advisories",
        "base": "https://tools.cisco.com/security/center/publicationListing.x",
        "search": "https://tools.cisco.com/security/center/publicationListing.x",
    },
    # Zoom
    "zoom video communications, inc.": {
        "name": "Zoom Security Bulletins",
        "base": "https://explore.zoom.us/en/trust/security/security-bulletin/",
        "search": "https://explore.zoom.us/en/trust/security/security-bulletin/",
    },
    # VMware / Broadcom
    "vmware, inc.": {
        "name": "VMware Security Advisories",
        "base": "https://www.vmware.com/security/advisories.html",
        "search": "https://www.vmware.com/security/advisories.html",
    },
    "broadcom": {
        "name": "Broadcom Security Advisories",
        "base": "https://support.broadcom.com/security-advisory",
        "search": "https://support.broadcom.com/security-advisory",
    },
    # Red Hat / IBM
    "red hat, inc.": {
        "name": "Red Hat Security Advisories",
        "base": "https://access.redhat.com/security/cve/{cve_id}",
        "search": "https://access.redhat.com/security/",
    },
    "ibm": {
        "name": "IBM Security Bulletins",
        "base": "https://www.ibm.com/support/pages/security-bulletin",
        "search": "https://www.ibm.com/support/pages/security-bulletin",
    },
    # Fortinet
    "fortinet": {
        "name": "Fortinet PSIRT Advisories",
        "base": "https://www.fortiguard.com/psirt",
        "search": "https://www.fortiguard.com/psirt",
    },
    # Palo Alto
    "palo alto networks": {
        "name": "Palo Alto Networks Security Advisories",
        "base": "https://security.paloaltonetworks.com/",
        "search": "https://security.paloaltonetworks.com/",
    },
    # Atlassian
    "atlassian": {
        "name": "Atlassian Security Advisories",
        "base": "https://confluence.atlassian.com/security",
        "search": "https://confluence.atlassian.com/security",
    },
    # Apache
    "apache software foundation": {
        "name": "Apache Security Advisories",
        "base": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "search": "https://www.apache.org/security/",
    },
    # OpenSSL
    "openssl software foundation": {
        "name": "OpenSSL Security Advisories",
        "base": "https://www.openssl.org/news/vulnerabilities.html",
        "search": "https://www.openssl.org/news/vulnerabilities.html",
    },
    # NGINX
    "f5, inc.": {
        "name": "NGINX/F5 Security Advisories",
        "base": "https://my.f5.com/manage/s/article/K000-series",
        "search": "https://my.f5.com/manage/s/article/K000-series",
    },
    # Intel
    "intel corporation": {
        "name": "Intel Security Advisories",
        "base": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa.html",
        "search": "https://www.intel.com/content/www/us/en/security-center/default.html",
    },
    # NVIDIA
    "nvidia corporation": {
        "name": "NVIDIA Security Bulletins",
        "base": "https://www.nvidia.com/en-us/security/",
        "search": "https://www.nvidia.com/en-us/security/",
    },
    # Python
    "python software foundation": {
        "name": "Python Security Advisories",
        "base": "https://python-security.readthedocs.io/",
        "search": "https://www.python.org/news/security/",
    },
    # Node.js
    "openjsf": {
        "name": "Node.js Security Releases",
        "base": "https://nodejs.org/en/blog/vulnerability/",
        "search": "https://nodejs.org/en/blog/vulnerability/",
    },
    # WordPress
    "wordpress": {
        "name": "WordPress Security",
        "base": "https://wordpress.org/news/category/security/",
        "search": "https://wordpress.org/news/category/security/",
    },
    # 7-Zip
    "igor pavlov": {
        "name": "7-Zip Release History",
        "base": "https://www.7-zip.org/history.txt",
        "search": "https://www.7-zip.org/history.txt",
    },
    # Wireshark
    "wireshark foundation": {
        "name": "Wireshark Security Advisories",
        "base": "https://www.wireshark.org/security/",
        "search": "https://www.wireshark.org/security/",
    },
    # Git
    "software freedom conservancy": {
        "name": "Git Security Advisories",
        "base": "https://github.com/git/git/security/advisories",
        "search": "https://github.com/git/git/security/advisories",
    },
    # JetBrains
    "jetbrains": {
        "name": "JetBrains Security Advisories",
        "base": "https://www.jetbrains.com/privacy-security/issues-fixed/",
        "search": "https://www.jetbrains.com/privacy-security/issues-fixed/",
    },
    # Slack / Salesforce
    "slack technologies, llc": {
        "name": "Slack Security Bulletins",
        "base": "https://slack.com/security",
        "search": "https://slack.com/security",
    },
    # Dropbox
    "dropbox, inc.": {
        "name": "Dropbox Security",
        "base": "https://dropbox.tech/security",
        "search": "https://dropbox.tech/security",
    },
    # WinRAR
    "win.rar gmbh": {
        "name": "WinRAR Release Notes",
        "base": "https://www.win-rar.com/whatsnew.html",
        "search": "https://www.win-rar.com/whatsnew.html",
    },
    # LibreOffice
    "the document foundation": {
        "name": "LibreOffice Security Advisories",
        "base": "https://www.libreoffice.org/about-us/security/advisories/",
        "search": "https://www.libreoffice.org/about-us/security/advisories/",
    },
    # Notepad++
    "don ho": {
        "name": "Notepad++ Releases",
        "base": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases",
        "search": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases",
    },
    # VLC
    "videolan": {
        "name": "VLC Security Advisories",
        "base": "https://www.videolan.org/security/",
        "search": "https://www.videolan.org/security/",
    },
    # TeamViewer
    "teamviewer": {
        "name": "TeamViewer Security Bulletins",
        "base": "https://www.teamviewer.com/en-us/trust-center/security-bulletins/",
        "search": "https://www.teamviewer.com/en-us/trust-center/security-bulletins/",
    },
}

# Software name keywords → advisory URL (fallback when publisher not matched)
_PRODUCT_ADVISORY: Dict[str, Dict[str, str]] = {
    "chrome":     {"name": "Chrome Releases", "base": "https://chromereleases.googleblog.com/"},
    "firefox":    {"name": "Mozilla Security", "base": "https://www.mozilla.org/en-US/security/advisories/"},
    "edge":       {"name": "Microsoft Edge Security", "base": "https://msrc.microsoft.com/update-guide/"},
    "openssl":    {"name": "OpenSSL Security", "base": "https://www.openssl.org/news/vulnerabilities.html"},
    "nginx":      {"name": "NGINX Security", "base": "https://nginx.org/en/security_advisories.html"},
    "apache":     {"name": "Apache Security", "base": "https://httpd.apache.org/security_report.html"},
    "openssh":    {"name": "OpenSSH Security", "base": "https://www.openssh.com/security.html"},
    "python":     {"name": "Python Security", "base": "https://www.python.org/news/security/"},
    "java":       {"name": "Oracle Java Security", "base": "https://www.oracle.com/security-alerts/"},
    "openjdk":    {"name": "OpenJDK Security", "base": "https://openjdk.org/groups/vulnerability/"},
    "git":        {"name": "Git Security", "base": "https://github.com/git/git/security/advisories"},
    "curl":       {"name": "curl Security", "base": "https://curl.se/docs/security.html"},
    "libssl":     {"name": "OpenSSL Security", "base": "https://www.openssl.org/news/vulnerabilities.html"},
    "libreoffice":{"name": "LibreOffice Security", "base": "https://www.libreoffice.org/about-us/security/advisories/"},
    "zoom":       {"name": "Zoom Security", "base": "https://explore.zoom.us/en/trust/security/security-bulletin/"},
    "teams":      {"name": "Microsoft Security", "base": "https://msrc.microsoft.com/update-guide/"},
    "node":       {"name": "Node.js Security", "base": "https://nodejs.org/en/blog/vulnerability/"},
    "vlc":        {"name": "VLC Security", "base": "https://www.videolan.org/security/"},
    "7-zip":      {"name": "7-Zip Releases", "base": "https://www.7-zip.org/history.txt"},
    "winrar":     {"name": "WinRAR Releases", "base": "https://www.win-rar.com/whatsnew.html"},
    "wireshark":  {"name": "Wireshark Security", "base": "https://www.wireshark.org/security/"},
    "putty":      {"name": "PuTTY Security", "base": "https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html"},
    "notepad++":  {"name": "Notepad++ Releases", "base": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases"},
    "teamviewer": {"name": "TeamViewer Bulletins", "base": "https://www.teamviewer.com/en-us/trust-center/security-bulletins/"},
}

# GitHub Security Advisory URL pattern (fallback for OSS packages)
_GITHUB_ADVISORY = "https://github.com/advisories?query={query}"
_NVD_ADVISORY    = "https://nvd.nist.gov/vuln/detail/{cve_id}"


def resolve_advisory(
    publisher: str,
    software_name: str,
    cve_id: str = "",
) -> Optional[Dict[str, str]]:
    """
    Return advisory info dict with keys:
      name   — human-readable advisory source name
      url    — direct or best-guess advisory URL
      source — 'publisher' | 'product' | 'nvd'

    Returns None if no match found (caller should fall back to NVD).
    """
    pub_lower = publisher.lower().strip()
    sw_lower  = software_name.lower().strip()

    # 1. Exact publisher match
    info = _PUBLISHER_ADVISORY.get(pub_lower)
    if info:
        url = info["base"]
        if "{cve_id}" in url and cve_id:
            url = url.replace("{cve_id}", cve_id)
        return {"name": info["name"], "url": url, "source": "publisher"}

    # 2. Partial publisher match (e.g. "Microsoft Corporation" → "microsoft")
    for key, info in _PUBLISHER_ADVISORY.items():
        if key in pub_lower or (len(key) > 4 and key.split()[0] in pub_lower):
            url = info["base"]
            if "{cve_id}" in url and cve_id:
                url = url.replace("{cve_id}", cve_id)
            return {"name": info["name"], "url": url, "source": "publisher"}

    # 3. Product name keyword match
    for keyword, info in _PRODUCT_ADVISORY.items():
        if keyword in sw_lower:
            url = info["base"]
            if "{cve_id}" in url and cve_id:
                url = url.replace("{cve_id}", cve_id)
            return {"name": info["name"], "url": url, "source": "product"}

    # 4. No match — return NVD as the canonical advisory source
    if cve_id:
        return {
            "name": "NVD Advisory",
            "url": _NVD_ADVISORY.replace("{cve_id}", cve_id),
            "source": "nvd",
        }
    return None


def enrich_rows_with_advisories(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Add a 'Vendor Advisory URL' field to each row by resolving the publisher.
    Modifies rows in-place and returns them.
    """
    for r in rows:
        publisher = str(r.get("Publisher", "") or "")
        sw_name   = str(r.get("Software Name", "") or "")
        cve_id    = str(r.get("CVE ID", "") or "")
        advisory  = resolve_advisory(publisher, sw_name, cve_id)
        if advisory:
            r["Vendor Advisory URL"]  = advisory["url"]
            r["Vendor Advisory Name"] = advisory["name"]
        else:
            r["Vendor Advisory URL"]  = ""
            r["Vendor Advisory Name"] = ""
    return rows


def advisory_summary(rows: List[Dict[str, str]]) -> Dict[str, int]:
    """
    Return counts of advisory source types across all rows.
    Useful for logging / report headers.
    """
    from collections import Counter
    c: Counter = Counter()
    publishers = {str(r.get("Publisher","") or "").lower().strip() for r in rows}
    for pub in publishers:
        info = _PUBLISHER_ADVISORY.get(pub)
        if info:
            c["publisher_matched"] += 1
        else:
            c["unmatched"] += 1
    return dict(c)
