"""
draugr_plugins.py — Plugin loader for Draugr.

Plugins live in a plugins/ directory next to draugr.py.
Each plugin is a Python file that defines one or more of:

  def enrich_row(row: dict) -> dict
      Called for every CVE row after enrichment. Return modified row.

  def score_modifier(row: dict, score: float) -> float
      Called after risk score is computed. Return modified score (0-100).

  def on_scan_complete(all_rows: list) -> list
      Called once when a scan finishes. Return (possibly modified) rows.

  def report_section(all_rows: list) -> str
      Return a markdown string appended to each report.

  PLUGIN_NAME = "My Plugin"          # required
  PLUGIN_VERSION = "1.0"             # optional
  PLUGIN_DESCRIPTION = "..."         # optional
"""
import importlib.util
import os
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


_PLUGINS_DIR_NAME = "plugins"
_loaded_plugins: List[Dict[str, Any]] = []
_load_errors:    List[str] = []


def _plugins_dir() -> Path:
    return Path(os.path.dirname(os.path.abspath(__file__))) / _PLUGINS_DIR_NAME


def load_plugins(plugins_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Discover and load all .py files in the plugins directory.
    Returns list of loaded plugin dicts.
    """
    global _loaded_plugins, _load_errors
    _loaded_plugins = []
    _load_errors    = []

    pdir = Path(plugins_dir) if plugins_dir else _plugins_dir()
    if not pdir.exists():
        return []

    for py_file in sorted(pdir.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        try:
            spec   = importlib.util.spec_from_file_location(py_file.stem, py_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            plugin: Dict[str, Any] = {
                "name":        getattr(module, "PLUGIN_NAME",        py_file.stem),
                "version":     getattr(module, "PLUGIN_VERSION",     "1.0"),
                "description": getattr(module, "PLUGIN_DESCRIPTION", ""),
                "file":        str(py_file),
                "module":      module,
                "enrich_row":         getattr(module, "enrich_row",         None),
                "score_modifier":     getattr(module, "score_modifier",     None),
                "on_scan_complete":   getattr(module, "on_scan_complete",   None),
                "report_section":     getattr(module, "report_section",     None),
            }
            _loaded_plugins.append(plugin)
        except Exception as e:
            _load_errors.append(f"{py_file.name}: {e}\n{traceback.format_exc()}")

    return _loaded_plugins


def get_loaded_plugins() -> List[Dict[str, Any]]:
    return _loaded_plugins


def get_load_errors() -> List[str]:
    return _load_errors


def apply_enrich_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Run all enrich_row hooks on a CVE row."""
    for plugin in _loaded_plugins:
        fn: Optional[Callable] = plugin.get("enrich_row")
        if fn:
            try:
                result = fn(row)
                if isinstance(result, dict):
                    row = result
            except Exception as e:
                pass   # plugin errors are non-fatal
    return row


def apply_score_modifier(row: Dict[str, Any], score: float) -> float:
    """Run all score_modifier hooks."""
    for plugin in _loaded_plugins:
        fn: Optional[Callable] = plugin.get("score_modifier")
        if fn:
            try:
                result = fn(row, score)
                if isinstance(result, (int, float)):
                    score = min(max(float(result), 0.0), 100.0)
            except Exception:
                pass
    return score


def apply_on_scan_complete(all_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run all on_scan_complete hooks."""
    for plugin in _loaded_plugins:
        fn: Optional[Callable] = plugin.get("on_scan_complete")
        if fn:
            try:
                result = fn(all_rows)
                if isinstance(result, list):
                    all_rows = result
            except Exception:
                pass
    return all_rows


def collect_report_sections(all_rows: List[Dict[str, Any]]) -> str:
    """Collect and concatenate all report_section contributions."""
    sections: List[str] = []
    for plugin in _loaded_plugins:
        fn: Optional[Callable] = plugin.get("report_section")
        if fn:
            try:
                result = fn(all_rows)
                if isinstance(result, str) and result.strip():
                    sections.append(f"## {plugin['name']} (plugin)\n\n{result.strip()}")
            except Exception:
                pass
    return "\n\n".join(sections)


def ensure_plugins_dir() -> Path:
    """Create the plugins directory and a sample plugin if it doesn't exist."""
    pdir = _plugins_dir()
    pdir.mkdir(exist_ok=True)

    sample = pdir / "_sample_plugin.py"
    if not sample.exists():
        sample.write_text(
            '"""\nSample Draugr plugin — rename (remove leading _) to activate.\n"""\n\n'
            'PLUGIN_NAME        = "Sample Plugin"\n'
            'PLUGIN_VERSION     = "1.0"\n'
            'PLUGIN_DESCRIPTION = "Example plugin showing available hooks"\n\n\n'
            'def enrich_row(row: dict) -> dict:\n'
            '    """\n'
            '    Called for every CVE row after standard enrichment.\n'
            '    Add custom fields, modify values, etc.\n'
            '    row keys include: CVE ID, Software Name, Software Version,\n'
            '    CVSS Base Score, Risk Score, ATT&CK Techniques, ...\n'
            '    """\n'
            '    # Example: tag internet-facing software\n'
            '    if "apache" in row.get("Software Name", "").lower():\n'
            '        row["Tags"] = "internet-facing"\n'
            '    return row\n\n\n'
            'def score_modifier(row: dict, score: float) -> float:\n'
            '    """\n'
            '    Called after risk score is computed.\n'
            '    Return a modified score in range 0-100.\n'
            '    """\n'
            '    # Example: boost score for internet-facing software\n'
            '    if row.get("Tags") == "internet-facing":\n'
            '        score = min(score * 1.1, 100.0)\n'
            '    return score\n\n\n'
            'def on_scan_complete(all_rows: list) -> list:\n'
            '    """\n'
            '    Called once when a full scan finishes.\n'
            '    Return (possibly filtered/modified) rows.\n'
            '    """\n'
            '    return all_rows\n\n\n'
            'def report_section(all_rows: list) -> str:\n'
            '    """\n'
            '    Return a markdown string appended as an extra section\n'
            '    in every generated report.\n'
            '    """\n'
            '    tagged = [r for r in all_rows if r.get("Tags")]\n'
            '    if not tagged:\n'
            '        return ""\n'
            '    return f"Found {len(tagged)} tagged findings.\\n"\n',
            encoding="utf-8",
        )
    return pdir
