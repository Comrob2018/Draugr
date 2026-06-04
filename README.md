# Draugr
Draugr is a PyQt6 desktop vulnerability intelligence tool that analyses software against multiple threat data sources — including the NVD, CISA Known Exploited Vulnerabilities (KEV) catalog, EPSS scores, and public exploit references — to compute a weighted risk score per CVE. It's designed for analysts and developers who need fast, local vulnerability intelligence without relying on asset inventories or complex CMDBs.

---

## 🚀 Features
- **NVD integration** — Queries CVE and CPE APIs directly using your API key.
- **CISA KEV overlay** — Flags known exploited vulnerabilities and adds metadata.
- **EPSS scoring** — Pulls exploit prediction scores for prioritisation.
- **Public exploit detection** — Identifies CVEs with known exploit references.
- **Weighted risk scoring** — Combines CVSS, EPSS, KEV, and exploit presence into a single 0–100 risk score.
- **Offline enrichment pipeline** — Optional local databases for CWE, CAPEC, ATT&CK, D3FEND, and NIST 800-53 mappings.
- **ICS/OT analysis** — Maps CWEs to MITRE ATT&CK for ICS techniques for operational technology environments.
- **Version deduplication** — Normalises version strings at parse time so `0.4` and `0.4.0` are treated as the same entry, avoiding duplicate scans.
- **Multi-format input** — Accepts CSV/TXT software inventories, CycloneDX JSON SBOMs, and SPDX JSON SBOMs.
- **Fleet support** — Aggregates scan history across multiple hosts with trend tracking and cross-system CVE heat maps.
- **Scheduled scanning** — Background scheduler for automated recurring scans with configurable intervals and job lists.
- **Plugin system** — Drop Python files into the `plugins/` directory to add custom enrichment, score modifiers, or report sections.
- **Alerting** — Email (SMTP), Slack, Microsoft Teams, and generic webhook notifications for KEV findings and risk threshold breaches.
- **Scan resume** — SQLite-backed cache resumes interrupted scans from where they left off.
- **PyQt6 GUI** — Dark/light theme support, progress tracking, results browser, and scan history viewer.
- **Headless CLI** — Full scan pipeline available without the GUI for automation and CI/CD integration.

---

## 🧩 Requirements

### Install dependencies:
```
pip install -r requirements.txt
```

#### Contents of requirements.txt:
```
PyQt6
requests
packaging
jsonschema
openpyxl
```

---

## ⚙️ Usage

### GUI
```
python draugr.py
```

### Headless CLI
```
python draugr.py --scan <software_list> --output <output_dir> [options]
```

#### CLI options:
| Flag | Description |
|---|---|
| `--scan` | Path to software list, SBOM, or CSV (required) |
| `--output` | Output directory (required) |
| `--kev` | Path to local KEV JSON file (optional) |
| `--api-key` | NVD API key (optional, increases rate limits) |
| `--otx-key` | AlienVault OTX API key (optional) |
| `--cpe-map` | Path to CPE mappings JSON (optional) |
| `--resources` | Path to enrichment databases folder (optional) |
| `--diff` | Previous scan CSV to diff against (optional) |
| `--multi-host` | Treat `--scan` as a glob/list of per-host CSVs |

### Scheduled scanning
```
python draugr_scheduler.py --init        # create default config
python draugr_scheduler.py               # run on configured interval
python draugr_scheduler.py --once        # run all jobs once and exit
```

---

## 📂 Input formats

### Prepare a software list file
See `sample_list.txt` or `sample_list.csv` in the resources folder.

Supported formats:
- **CSV with headers** — `Name, Version, Publisher, Install Date` (exports from Hapy, SCCM, PDQ, Qualys, etc.)
- **Headerless CSV** — `product, version`
- **Plain text** — one product name per line
- **CycloneDX JSON** — SBOM format (1.4 and 1.5)
- **SPDX JSON** — SBOM format (2.3)

### Optionally download the CISA KEV JSON feed:
```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### Optionally create a cpe_mappings.json file to override heuristic CPE matching:
```json
{
  "apache tomcat":  "apache:tomcat",
  "openssl":        "openssl:openssl",
  "microsoft edge": "microsoft:edge_chromium"
}
```

---

## 📂 Output

All output is written to the configured output directory under `reports/` and `logs/`.

### CSV report
Contains all CVE details, risk scores, exploit indicators, KEV flags, MITRE ATT&CK and ICS codes.

### HTML reports
| Report | Description |
|---|---|
| Executive Report | C-suite focused summary with risk matrix, key findings, and remediation priorities |
| Technical Report | Detailed security assessment with mitigations, NIST 800-53 controls, and ATT&CK mappings |
| Red Team Report | Attack path analysis and target profiling for offensive security use |
| Fleet Report | Cross-system CVE heat map and trend analysis across multiple hosts |
| Diff Report | Delta between two scans showing new, resolved, and worsened findings |

### Excel
| File | Description |
|---|---|
| POA&M | Plan of Action and Milestones for tracked CVEs |

### SBOM
| File | Description |
|---|---|
| CycloneDX JSON | Software Bill of Materials in CycloneDX 1.5 format with vulnerability annotations |

### Logs
| File | Description |
|---|---|
| Scan Log | Full output from the scan log window |
| Error Log | Errors encountered during the scan |

---

## 🖥️ Results Browser

The Results Browser tab provides a searchable, filterable view of scan findings. From the source bar you can:

- **📂 Load CSV** — Load any previous Draugr scan CSV into the browser
- **📄 Generate Reports** — Generate all HTML reports, POA&M, and SBOM from the currently loaded results
- **🔄 Rescan** *(scan area)* — Re-run a fresh scan against the software list from the currently loaded CSV, using all current configuration settings

The Show MEDIUM, Show LOW, and Show Unverified filters are available in the Scan Log tab toolbar and control what severity levels are written to the log during an active scan.

---

## 🧠 Optional enrichment databases

Place these JSON files in the `resources/` directory for deeper analysis:
```
cwe_db.json
capec_db.json
defend_db.json
nist_db.json
```
These enable CWE lineage expansion and mapping to MITRE ATT&CK, D3FEND, and NIST 800-53 frameworks.

---

## 🔌 Plugins

Drop `.py` files into the `plugins/` directory to extend Draugr. Each plugin can implement any of these hooks:

| Hook | Description |
|---|---|
| `enrich_row(row)` | Called for every CVE row after enrichment — add or modify fields |
| `score_modifier(row, score)` | Called after risk score is computed — return a modified score (0–100) |
| `on_scan_complete(all_rows)` | Called once when a scan finishes — return modified row list |
| `report_section(all_rows)` | Return a markdown string appended to every generated report |

A sample plugin is created automatically in `plugins/_sample_plugin.py` on first run.

---

## 🔔 Alerting

Configure alerting in `draugr_alerts.json`. Supported channels:

- **SMTP email** — Plain text and HTML with full CVE detail tables
- **Slack** — Block Kit formatted cards with severity colour and links
- **Microsoft Teams** — Adaptive Card format
- **Generic webhook** — JSON POST to any endpoint

Alerts trigger on: new KEV-listed CVEs, risk score threshold breaches, new findings on a previously clean system, and newly KEV-listed CVEs detected in a diff.

---

## 📋 Changelog

See `CHANGELOG.md` for full version history.