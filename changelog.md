# Draugr — Changelog

-----

## 3.2.0
> Project restructure and report accuracy fixes

- Reorganised companion modules into subdirectories: `core/`, `reports/`, `intelligence/`
- `core/` — `draugr_themes`, `draugr_plugins`, `draugr_cache`, `draugr_scheduler`
- `reports/` — `draugr_reports`, `draugr_sbom`, `draugr_poam`, `draugr_fleet`, `draugr_diff`
- `intelligence/` — `draugr_ics`, `draugr_advisories`, `draugr_alerts`, `draugr_remediation`
- All imports in `draugr.py` and `draugr_reports.py` updated to use explicit package paths (e.g. `from core.draugr_themes import ...`)
- `sys.path` bootstrap block retained in `draugr.py` for runtime resolution; removed from `draugr_reports.py` since explicit imports are now used
- `pyrightconfig.json` added to project root to resolve Pylance import errors for the subdirectory structure
- Fixed CVE total mismatch between donut chart and report summary — rows with unrecognised or missing CVSS severity were silently dropped from `sev_counts`, causing `total_s` in the donut to be lower than `total_cves`
- Added `OTHER` bucket to `sev_counts` in both executive and technical reports — any severity not matching CRITICAL, HIGH, MEDIUM, or LOW is now captured there
- Added `INFO` and `OTHER` segments to `_svg_donut()` — rendered in grey; only appear if non-zero; `total_s` now always equals `total_cves`

-----

## 3.1.0

> UI reorganisation and polish pass

- Moved Copy Log and Clear Log buttons into the Scan Log tab toolbar
- Moved Show MEDIUM, Show LOW, and Show Unverified checkboxes into the Scan Log tab toolbar, alongside Copy Log and Clear Log
- Generate Reports and Rescan buttons are now disabled at startup and only enabled once results are loaded
- Rescan button is disabled while a scan is in progress
- Added `_update_data_action_buttons()` helper to centralise button state management
- Report stem now derived from the actual loaded CSV filename rather than parsing the source label text; falls back to a timestamp for live scan results
- Added status bar feedback during report generation (“Generating reports…”, “Reports generated.”, “Report generation failed.”)
- Renamed `self._gen_reports_btn` → `self.gen_reports_btn` for naming consistency with other button attributes
- Replaced flat Unicode icons (▶, ■, Δ) on Start Scan, Stop Scan, and Compare Scans with emoji equivalents (▶️, ⏹️, 🔀) to match the visual weight of other buttons
- All scan area button setText reset calls updated to use the new emoji icon

-----

## 3.0.3

> Button layout and style consistency

- Rescan button moved from Results Browser source bar to the main scan area button row
- Generate Reports and Rescan remain in their respective locations; Compare Scans and Scan History stay in the scan area
- Removed colour `.replace()` overrides from Skip Current, Compare Scans, and Scan History buttons — all scan area buttons now use a uniform `ACTION_BTN_STYLE`

-----

## 3.0.2

> Version deduplication in software parsing

- Added `_normalise_version()` — pads version strings to 3 dot-separated segments for deduplication key comparison (`0.4` and `0.4.0` are treated as identical; `0.4.0` and `1.4.0` remain distinct)
- Refactored `parse_software_input()` to collect parser output into `raw` before running a deduplication pass, rather than early-returning from each branch
- When two entries normalise to the same key, the most specific version string (most dot segments) is kept for better NVD/CPE matching
- Deduplication applies to all input formats: CSV, CycloneDX JSON, SPDX JSON, and the new Rescan path

-----

## 3.0.1

> Rescan from loaded CSV

- Added Rescan button to the Results Browser source bar (later moved to scan area in 3.0.3)
- Added `_rescan_from_loaded_csv()` — reconstructs the software list from `self._scan_rows`, deduplicates by `(name, version, publisher)`, and passes it directly to `_start_scan()` via the new `software_override` parameter
- Added `software_override` optional parameter to `_start_scan()` — when supplied, skips file existence validation and `parse_software_input()` call; all other scan logic (output paths, worker setup, report generation) runs identically
- Rescan path covered by the same deduplication fix introduced in 3.0.2

-----

## 3.0.0

> Clean version reset — UI and report improvements

- Version reset from 2.2.1 to 3.0.0 to reconcile version string drift (splash screen had been showing v2.8.2 independently of `DRAUGR_VERSION`)
- Splash screen version string converted from a hardcoded literal to an f-string using `DRAUGR_VERSION` — single source of truth for all version references
- Added Generate Reports button to the Results Browser source bar
- Added `_generate_reports_from_loaded_csv()` — generates Executive, Technical, and Red Team HTML reports (plus POA&M and SBOM if available) from any loaded results, whether from a live scan or a loaded CSV

-----

## previous versions
> 2.2.1 and prior
