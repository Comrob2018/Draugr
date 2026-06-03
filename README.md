## Draugr  
Draugr is a PyQt6 desktop vulnerability intelligence tool that analyzes software against multiple threat data sources — including the NVD,  
CISA Known Exploited Vulnerabilities (KEV) catalog, EPSS scores, and public exploit references — to compute a weighted risk score per CVE.  
It’s designed for analysts and developers who need fast, local vulnerability intelligence without relying on asset inventories or complex CMDBs.  

🚀 Features  
NVD integration — Queries CVE and CPE APIs directly using your API key.  
CISA KEV overlay — Flags known exploited vulnerabilities and adds metadata.  
EPSS scoring — Pulls exploit prediction scores for prioritization.  
Public exploit detection — Identifies CVEs with known exploit references.  
Weighted risk scoring — Combines CVSS, EPSS, KEV, and exploit presence.  
Offline enrichment pipeline — Optional local databases for CWE, CAPEC, ATT&CK, D3FEND, and NIST 800‑53 mappings.  
CSV export — Generates analyst‑ready reports.  
PyQt6 GUI — Clean, modular interface with progress tracking and theme support.  

🧩 Requirements  
Install dependencies:  

bash  
pip install -r requirements.txt  
requirements.txt  

```  
PyQt6  
requests  
packaging  
jsonschema  # optional for enrichment validation
```
⚙️ Usage  
Prepare a software list file (see sample_software_list.txt format).  
Optionally download the CISA KEV JSON feed:  

```  
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json  
```
Optionally create a cpe_mappings.json file to override heuristic matching:  

json  
```
{  
  "apache tomcat": "apache:tomcat",  
  "openssl": "openssl:openssl",  
  "microsoft edge": "microsoft:edge_chromium"  
}
```  
Run the scanner:  
```
python draugr.py  
```

📂 Output  
CSV report — Contains CVE details, risk scores, exploit indicators, and KEV flags.  
HTML Reports  
Executive Report- All information needed for an excutive style report. Limit amounts of data to highest risk cves  
Comprehensive Report - No limit to the amount of information included.  
GUI view — Displays progress, results, and export options.  

🧠 Optional Enrichment Databases  
Place these JSON files in the resources/ directory for deeper analysis:  
```
cwe_db.json  
capec_db.json  
defend_db.json  
nist_db.json  
```
These enable lineage expansion and mapping to MITRE ATT&CK and D3FEND frameworks.  

🛡️ License  
MIT License — free for modification and commercial use with attribution.  
