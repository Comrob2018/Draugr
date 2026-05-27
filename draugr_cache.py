"""
draugr_cache.py — SQLite-backed NVD response cache and scan resume support.

Provides:
  - NVDCache: caches raw NVD API JSON responses keyed by URL+params hash
  - ScanCache: persists per-software scan results so interrupted scans resume
              from where they left off rather than restarting from scratch
"""
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Default cache location: %APPDATA%/Draugr/cache.db on Windows,
# ~/.local/share/draugr/cache.db on Linux/macOS
def _default_cache_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / "Draugr"
    d.mkdir(parents=True, exist_ok=True)
    return d


_SCHEMA_NVD = """
CREATE TABLE IF NOT EXISTS nvd_cache (
    cache_key   TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    params_json TEXT NOT NULL,
    response    TEXT NOT NULL,
    fetched_at  REAL NOT NULL,
    ttl_seconds REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nvd_fetched ON nvd_cache(fetched_at);
"""

_SCHEMA_SCAN = """
CREATE TABLE IF NOT EXISTS scan_progress (
    session_id  TEXT NOT NULL,
    sw_key      TEXT NOT NULL,       -- "name||version||publisher"
    status      TEXT NOT NULL,       -- 'done' | 'no_cves'
    rows_json   TEXT NOT NULL,       -- JSON-serialised list of row dicts
    scanned_at  REAL NOT NULL,
    PRIMARY KEY (session_id, sw_key)
);
CREATE INDEX IF NOT EXISTS idx_scan_session ON scan_progress(session_id);
"""

_SCHEMA_FP = """
CREATE TABLE IF NOT EXISTS false_positives (
    cve_id      TEXT NOT NULL,
    sw_name     TEXT NOT NULL,
    reason      TEXT,
    added_at    REAL NOT NULL,
    PRIMARY KEY (cve_id, sw_name)
);
"""


class DraugrDB:
    """
    Single SQLite connection wrapper for all Draugr persistent storage:
      - NVD API response cache
      - Scan resume / progress cache
      - False positive suppression list
    """

    # NVD CPE dictionary entries change rarely; CVE data changes more often
    NVD_CPE_TTL  = 7 * 86400   # 7 days
    NVD_CVE_TTL  = 1 * 86400   # 1 day
    EPSS_TTL     = 6 * 3600    # 6 hours
    SCAN_TTL     = 24 * 3600   # resume window: 24 hours

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = str(_default_cache_dir() / "draugr_cache.db")
        self.db_path = db_path
        self._con: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def connect(self) -> None:
        self._con = sqlite3.connect(self.db_path, check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=NORMAL")
        self._con.executescript(_SCHEMA_NVD)
        self._con.executescript(_SCHEMA_SCAN)
        self._con.executescript(_SCHEMA_FP)
        self._con.commit()

    def close(self) -> None:
        if self._con:
            self._con.close()
            self._con = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    @property
    def con(self) -> sqlite3.Connection:
        if self._con is None:
            self.connect()
        return self._con

    # ------------------------------------------------------------------
    # NVD response cache
    # ------------------------------------------------------------------
    @staticmethod
    def _cache_key(url: str, params: Dict[str, Any]) -> str:
        raw = url + json.dumps(params, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get_nvd(self, url: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return cached response if still fresh, else None."""
        key = self._cache_key(url, params)
        row = self.con.execute(
            "SELECT response, fetched_at, ttl_seconds FROM nvd_cache WHERE cache_key=?",
            (key,)
        ).fetchone()
        if row is None:
            return None
        response_json, fetched_at, ttl = row
        if time.time() - fetched_at > ttl:
            self.con.execute("DELETE FROM nvd_cache WHERE cache_key=?", (key,))
            self.con.commit()
            return None
        try:
            return json.loads(response_json)
        except json.JSONDecodeError:
            return None

    def put_nvd(self, url: str, params: Dict[str, Any], response: Dict[str, Any],
                ttl: Optional[float] = None) -> None:
        """Store a response. TTL defaults based on URL type."""
        key = self._cache_key(url, params)
        if ttl is None:
            if "cpes" in url:
                ttl = self.NVD_CPE_TTL
            elif "epss" in url:
                ttl = self.EPSS_TTL
            else:
                ttl = self.NVD_CVE_TTL
        self.con.execute(
            """INSERT OR REPLACE INTO nvd_cache
               (cache_key, url, params_json, response, fetched_at, ttl_seconds)
               VALUES (?,?,?,?,?,?)""",
            (key, url, json.dumps(params, sort_keys=True),
             json.dumps(response), time.time(), ttl)
        )
        self.con.commit()

    def purge_expired_nvd(self) -> int:
        """Remove all expired NVD cache entries. Returns rows deleted."""
        now = time.time()
        cur = self.con.execute(
            "DELETE FROM nvd_cache WHERE (fetched_at + ttl_seconds) < ?", (now,)
        )
        self.con.commit()
        return cur.rowcount

    def cache_stats(self) -> Dict[str, int]:
        """Return counts of cached entries by table."""
        nvd_total  = self.con.execute("SELECT COUNT(*) FROM nvd_cache").fetchone()[0]
        nvd_fresh  = self.con.execute(
            "SELECT COUNT(*) FROM nvd_cache WHERE (fetched_at + ttl_seconds) >= ?",
            (time.time(),)
        ).fetchone()[0]
        scan_total = self.con.execute("SELECT COUNT(*) FROM scan_progress").fetchone()[0]
        fp_total   = self.con.execute("SELECT COUNT(*) FROM false_positives").fetchone()[0]
        return {
            "nvd_total": nvd_total,
            "nvd_fresh": nvd_fresh,
            "scan_resume_entries": scan_total,
            "false_positives": fp_total,
        }

    # ------------------------------------------------------------------
    # Scan resume / progress cache
    # ------------------------------------------------------------------
    @staticmethod
    def _sw_key(name: str, version: str, publisher: str = "") -> str:
        return f"{name.strip()}||{version.strip()}||{publisher.strip()}"

    def session_id_for(self, sw_list: List[Tuple[str, str, str, str]]) -> str:
        """
        Derive a deterministic session ID from the sorted software list.
        Same list → same ID, allowing resume across restarts.
        """
        canonical = json.dumps(
            sorted((n, v, p) for n, v, p, _ in sw_list),
            sort_keys=True
        )
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def get_cached_rows(self, session_id: str, name: str, version: str,
                        publisher: str = "") -> Optional[List[Dict[str, Any]]]:
        """Return cached rows for this software item if the session is still fresh."""
        key = self._sw_key(name, version, publisher)
        row = self.con.execute(
            "SELECT rows_json, scanned_at FROM scan_progress WHERE session_id=? AND sw_key=?",
            (session_id, key)
        ).fetchone()
        if row is None:
            return None
        rows_json, scanned_at = row
        if time.time() - scanned_at > self.SCAN_TTL:
            return None
        try:
            return json.loads(rows_json)
        except json.JSONDecodeError:
            return None

    def put_cached_rows(self, session_id: str, name: str, version: str,
                        publisher: str, rows: List[Dict[str, Any]]) -> None:
        """Persist scanned rows for this software item."""
        key = self._sw_key(name, version, publisher)
        self.con.execute(
            """INSERT OR REPLACE INTO scan_progress
               (session_id, sw_key, status, rows_json, scanned_at)
               VALUES (?,?,?,?,?)""",
            (session_id, key, "done", json.dumps(rows), time.time())
        )
        self.con.commit()

    def completed_keys(self, session_id: str) -> set:
        """Return set of sw_keys already completed in this session."""
        rows = self.con.execute(
            "SELECT sw_key FROM scan_progress WHERE session_id=?",
            (session_id,)
        ).fetchall()
        return {r[0] for r in rows}

    def clear_session(self, session_id: str) -> None:
        """Remove all resume data for a session (e.g. after successful completion)."""
        self.con.execute(
            "DELETE FROM scan_progress WHERE session_id=?", (session_id,)
        )
        self.con.commit()

    def clear_all_sessions(self) -> None:
        self.con.execute("DELETE FROM scan_progress")
        self.con.commit()

    # ------------------------------------------------------------------
    # False positive suppression
    # ------------------------------------------------------------------
    def add_false_positive(self, cve_id: str, sw_name: str, reason: str = "") -> None:
        self.con.execute(
            """INSERT OR REPLACE INTO false_positives
               (cve_id, sw_name, reason, added_at) VALUES (?,?,?,?)""",
            (cve_id.upper().strip(), sw_name.strip(), reason, time.time())
        )
        self.con.commit()

    def remove_false_positive(self, cve_id: str, sw_name: str) -> None:
        self.con.execute(
            "DELETE FROM false_positives WHERE cve_id=? AND sw_name=?",
            (cve_id.upper().strip(), sw_name.strip())
        )
        self.con.commit()

    def is_false_positive(self, cve_id: str, sw_name: str) -> bool:
        row = self.con.execute(
            "SELECT 1 FROM false_positives WHERE cve_id=? AND sw_name=?",
            (cve_id.upper().strip(), sw_name.strip())
        ).fetchone()
        return row is not None

    def all_false_positives(self) -> List[Dict[str, Any]]:
        rows = self.con.execute(
            "SELECT cve_id, sw_name, reason, added_at FROM false_positives ORDER BY added_at DESC"
        ).fetchall()
        return [
            {"cve_id": r[0], "sw_name": r[1], "reason": r[2], "added_at": r[3]}
            for r in rows
        ]

    def import_false_positives(self, path: str) -> int:
        """
        Import false positives from a JSON file.
        Format: [{"cve_id": "CVE-...", "sw_name": "...", "reason": "..."}, ...]
        Returns count imported.
        """
        with open(path, "r", encoding="utf-8") as f:
            entries = json.load(f)
        count = 0
        for e in entries:
            cve_id  = str(e.get("cve_id", "") or "").strip()
            sw_name = str(e.get("sw_name", "") or "").strip()
            reason  = str(e.get("reason", "") or "")
            if cve_id and sw_name:
                self.add_false_positive(cve_id, sw_name, reason)
                count += 1
        return count

    def export_false_positives(self, path: str) -> int:
        """Export false positives to a JSON file. Returns count exported."""
        entries = self.all_false_positives()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2)
        return len(entries)


# Module-level singleton — lazily initialised on first use
_db_instance: Optional[DraugrDB] = None

def get_db() -> DraugrDB:
    global _db_instance
    if _db_instance is None:
        _db_instance = DraugrDB()
        _db_instance.connect()
    return _db_instance

# ======================================================================
#  SCAN HISTORY / TREND TRACKING
# ======================================================================

_SCHEMA_HISTORY = """
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id       TEXT PRIMARY KEY,     -- UUID-style: system_id + timestamp
    system_id     TEXT NOT NULL,        -- extracted from filename e.g. "agent_1"
    system_label  TEXT NOT NULL,        -- display name, same as system_id initially
    scan_date     TEXT NOT NULL,        -- ISO date YYYY-MM-DD
    scan_ts       REAL NOT NULL,        -- unix timestamp of scan
    input_file    TEXT NOT NULL,        -- original filename
    total_cves    INTEGER NOT NULL,
    critical      INTEGER NOT NULL DEFAULT 0,
    high          INTEGER NOT NULL DEFAULT 0,
    medium        INTEGER NOT NULL DEFAULT 0,
    low           INTEGER NOT NULL DEFAULT 0,
    kev_count     INTEGER NOT NULL DEFAULT 0,
    exploit_count INTEGER NOT NULL DEFAULT 0,
    max_risk      REAL    NOT NULL DEFAULT 0.0,
    avg_risk      REAL    NOT NULL DEFAULT 0.0,
    software_count INTEGER NOT NULL DEFAULT 0,
    rows_json     TEXT    NOT NULL      -- full scan rows for historical diff
);
CREATE INDEX IF NOT EXISTS idx_history_system  ON scan_history(system_id);
CREATE INDEX IF NOT EXISTS idx_history_date    ON scan_history(scan_date);
CREATE INDEX IF NOT EXISTS idx_history_ts      ON scan_history(scan_ts);

CREATE TABLE IF NOT EXISTS system_registry (
    system_id     TEXT PRIMARY KEY,
    system_label  TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    scan_count    INTEGER NOT NULL DEFAULT 0
);
"""

_SCHEMA_CPE_LEARN = """
CREATE TABLE IF NOT EXISTS cpe_learned (
    sw_key        TEXT PRIMARY KEY,   -- normalize_text(name)
    cpe_string    TEXT NOT NULL,      -- e.g. "microsoft:edge"
    confidence    REAL NOT NULL,
    hit_count     INTEGER NOT NULL DEFAULT 1,
    last_seen     REAL NOT NULL
);
"""


def extract_system_id(filename: str) -> str:
    """
    Extract a stable system identifier from a Hapy (or similar) inventory filename.

    Rules (applied in order):
      1. Take the filename stem (no extension).
      2. Strip leading 'hapy_software_' prefix if present (case-insensitive).
      3. Strip trailing timestamp suffix _YYYYMMDD_HHMMSS (underscore + 8 digits +
         underscore + 6 digits) if present.
      4. If nothing remains after stripping, return the original stem.

    Examples
    --------
    hapy_software_agent_1_20260526_062202  →  agent_1
    hapy_software_SERVER_ROOM_A_20260526_062202  →  SERVER_ROOM_A
    hapy_software_WORKSTATION-01_20260526_062202  →  WORKSTATION-01
    agent_1_20260526_062202  →  agent_1
    plain_inventory  →  plain_inventory
    myserver  →  myserver
    """
    import re as _re
    stem = Path(filename).stem   # drop extension

    # Step 1 — strip hapy_software_ prefix (case-insensitive)
    cleaned = _re.sub(r"(?i)^hapy_software_", "", stem)

    # Step 2 — strip trailing _YYYYMMDD_HHMMSS
    cleaned = _re.sub(r"_\d{8}_\d{6}$", "", cleaned)

    # Step 3 — if nothing survived, fall back to original stem
    return cleaned.strip("_") or stem


class TrendDB:
    """
    Mixin-style class that extends DraugrDB with trend / history methods.
    Not a separate connection — call connect() on DraugrDB first.
    """

    def _init_trend_schema(self) -> None:
        self.con.executescript(_SCHEMA_HISTORY)
        self.con.executescript(_SCHEMA_CPE_LEARN)
        self.con.commit()

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------
    def save_scan(
        self,
        system_id: str,
        input_file: str,
        rows: List[Dict[str, Any]],
        system_label: str = "",
    ) -> str:
        """
        Persist a completed scan into the history table.
        Returns the scan_id generated.
        """
        import datetime as _dt

        now     = _dt.datetime.now()
        scan_id = f"{system_id}_{now.strftime('%Y%m%d_%H%M%S')}"
        label   = system_label or system_id
        date_s  = now.strftime("%Y-%m-%d")
        ts      = now.timestamp()

        # Aggregate stats
        total   = len(rows)
        crit    = sum(1 for r in rows if str(r.get("CVSS Severity","")).upper() == "CRITICAL")
        high    = sum(1 for r in rows if str(r.get("CVSS Severity","")).upper() == "HIGH")
        med     = sum(1 for r in rows if str(r.get("CVSS Severity","")).upper() == "MEDIUM")
        low     = sum(1 for r in rows if str(r.get("CVSS Severity","")).upper() == "LOW")
        kev     = sum(1 for r in rows if str(r.get("Known Exploited Vulnerability","")).upper() == "YES")
        expl    = sum(1 for r in rows if str(r.get("Public Exploit","")).upper() == "YES")
        sw_set  = {str(r.get("Software Name","")).strip() for r in rows}

        scores  = [float(str(r.get("Risk Score",0) or 0)) for r in rows]
        max_rs  = max(scores) if scores else 0.0
        avg_rs  = (sum(scores) / len(scores)) if scores else 0.0

        self.con.execute(
            """INSERT OR REPLACE INTO scan_history
               (scan_id, system_id, system_label, scan_date, scan_ts,
                input_file, total_cves, critical, high, medium, low,
                kev_count, exploit_count, max_risk, avg_risk,
                software_count, rows_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, system_id, label, date_s, ts,
             str(input_file), total, crit, high, med, low,
             kev, expl, round(max_rs, 1), round(avg_rs, 1),
             len(sw_set), json.dumps(rows))
        )

        # Update system registry
        self.con.execute(
            """INSERT INTO system_registry (system_id, system_label, first_seen, last_seen, scan_count)
               VALUES (?,?,?,?,1)
               ON CONFLICT(system_id) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 scan_count=scan_count+1,
                 system_label=excluded.system_label""",
            (system_id, label, date_s, date_s)
        )
        self.con.commit()
        return scan_id

    def get_scan_history(
        self,
        system_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return scan history for a system, newest first."""
        rows = self.con.execute(
            """SELECT scan_id, system_id, system_label, scan_date, scan_ts,
                      input_file, total_cves, critical, high, medium, low,
                      kev_count, exploit_count, max_risk, avg_risk, software_count
               FROM scan_history
               WHERE system_id=?
               ORDER BY scan_ts DESC
               LIMIT ?""",
            (system_id, limit)
        ).fetchall()
        cols = ["scan_id","system_id","system_label","scan_date","scan_ts",
                "input_file","total_cves","critical","high","medium","low",
                "kev_count","exploit_count","max_risk","avg_risk","software_count"]
        return [dict(zip(cols, r)) for r in rows]

    def get_scan_rows(self, scan_id: str) -> List[Dict[str, Any]]:
        """Return the full row list for a historical scan (for diffing)."""
        row = self.con.execute(
            "SELECT rows_json FROM scan_history WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if row is None:
            return []
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return []

    def get_all_systems(self) -> List[Dict[str, Any]]:
        """Return all known systems from the registry."""
        rows = self.con.execute(
            """SELECT system_id, system_label, first_seen, last_seen, scan_count
               FROM system_registry ORDER BY last_seen DESC"""
        ).fetchall()
        cols = ["system_id","system_label","first_seen","last_seen","scan_count"]
        return [dict(zip(cols, r)) for r in rows]

    def get_trend_series(self, system_id: str) -> List[Dict[str, Any]]:
        """
        Return time-series trend data for a system: one record per scan,
        oldest first. Suitable for charting.
        """
        rows = self.con.execute(
            """SELECT scan_date, scan_ts, total_cves, critical, high, medium, low,
                      kev_count, exploit_count, max_risk, avg_risk, software_count
               FROM scan_history
               WHERE system_id=?
               ORDER BY scan_ts ASC""",
            (system_id,)
        ).fetchall()
        cols = ["scan_date","scan_ts","total_cves","critical","high","medium","low",
                "kev_count","exploit_count","max_risk","avg_risk","software_count"]
        return [dict(zip(cols, r)) for r in rows]

    def get_latest_scan_id(self, system_id: str) -> Optional[str]:
        """Return the scan_id of the most recent scan for a system."""
        row = self.con.execute(
            "SELECT scan_id FROM scan_history WHERE system_id=? ORDER BY scan_ts DESC LIMIT 1",
            (system_id,)
        ).fetchone()
        return row[0] if row else None

    def get_previous_scan_id(self, system_id: str, before_scan_id: str) -> Optional[str]:
        """Return the scan_id immediately preceding the given scan_id."""
        ts_row = self.con.execute(
            "SELECT scan_ts FROM scan_history WHERE scan_id=?", (before_scan_id,)
        ).fetchone()
        if not ts_row:
            return None
        row = self.con.execute(
            """SELECT scan_id FROM scan_history
               WHERE system_id=? AND scan_ts < ?
               ORDER BY scan_ts DESC LIMIT 1""",
            (system_id, ts_row[0])
        ).fetchone()
        return row[0] if row else None

    def rename_system(self, system_id: str, new_label: str) -> None:
        """Update the display label for a system."""
        self.con.execute(
            "UPDATE system_registry SET system_label=? WHERE system_id=?",
            (new_label, system_id)
        )
        self.con.execute(
            "UPDATE scan_history SET system_label=? WHERE system_id=?",
            (new_label, system_id)
        )
        self.con.commit()

    def delete_system_history(self, system_id: str) -> int:
        """Delete all history for a system. Returns rows deleted."""
        cur = self.con.execute(
            "DELETE FROM scan_history WHERE system_id=?", (system_id,)
        )
        self.con.execute(
            "DELETE FROM system_registry WHERE system_id=?", (system_id,)
        )
        self.con.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # CPE auto-learning
    # ------------------------------------------------------------------
    def learn_cpe(self, sw_name: str, cpe_string: str, confidence: float) -> None:
        """Record a successful CPE match for future scans."""
        key = sw_name.lower().strip()
        self.con.execute(
            """INSERT INTO cpe_learned (sw_key, cpe_string, confidence, hit_count, last_seen)
               VALUES (?,?,?,1,?)
               ON CONFLICT(sw_key) DO UPDATE SET
                 cpe_string=CASE WHEN excluded.confidence > cpe_learned.confidence
                                 THEN excluded.cpe_string ELSE cpe_learned.cpe_string END,
                 confidence=MAX(cpe_learned.confidence, excluded.confidence),
                 hit_count=hit_count+1,
                 last_seen=excluded.last_seen""",
            (key, cpe_string, confidence, time.time())
        )
        self.con.commit()

    def get_learned_cpe(self, sw_name: str, min_confidence: float = 0.3) -> Optional[str]:
        """
        Return a previously learned CPE string for this software name,
        if confidence meets the threshold.
        """
        key = sw_name.lower().strip()
        row = self.con.execute(
            "SELECT cpe_string, confidence FROM cpe_learned WHERE sw_key=? AND confidence>=?",
            (key, min_confidence)
        ).fetchone()
        return row[0] if row else None

    def get_all_learned_cpes(self) -> List[Dict[str, Any]]:
        rows = self.con.execute(
            "SELECT sw_key, cpe_string, confidence, hit_count, last_seen FROM cpe_learned ORDER BY hit_count DESC"
        ).fetchall()
        cols = ["sw_key","cpe_string","confidence","hit_count","last_seen"]
        return [dict(zip(cols, r)) for r in rows]

    def export_learned_cpes(self, path: str) -> int:
        """Export learned CPE mappings to a cpe_mappings.json-compatible file."""
        entries = self.get_all_learned_cpes()
        # Format: {sw_key: "vendor:product"}
        mapping = {e["sw_key"]: e["cpe_string"] for e in entries if e["confidence"] >= 0.4}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2)
        return len(mapping)


# Patch TrendDB methods into DraugrDB
DraugrDB.save_scan             = TrendDB.save_scan
DraugrDB.get_scan_history      = TrendDB.get_scan_history
DraugrDB.get_scan_rows         = TrendDB.get_scan_rows
DraugrDB.get_all_systems       = TrendDB.get_all_systems
DraugrDB.get_trend_series      = TrendDB.get_trend_series
DraugrDB.get_latest_scan_id    = TrendDB.get_latest_scan_id
DraugrDB.get_previous_scan_id  = TrendDB.get_previous_scan_id
DraugrDB.rename_system         = TrendDB.rename_system
DraugrDB.delete_system_history = TrendDB.delete_system_history
DraugrDB.learn_cpe             = TrendDB.learn_cpe
DraugrDB.get_learned_cpe       = TrendDB.get_learned_cpe
DraugrDB.get_all_learned_cpes  = TrendDB.get_all_learned_cpes
DraugrDB.export_learned_cpes   = TrendDB.export_learned_cpes
DraugrDB._init_trend_schema    = TrendDB._init_trend_schema


# Patch connect() to also init trend schema
_original_connect = DraugrDB.connect
def _patched_connect(self) -> None:
    _original_connect(self)
    self._init_trend_schema()
DraugrDB.connect = _patched_connect
