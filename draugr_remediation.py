"""
draugr_remediation.py — Remediation tracking for Draugr.

Stores per-finding remediation state in the Draugr SQLite database,
closing the loop between vulnerability identification and resolution.

Schema
------
remediation_items table (one row per CVE + software combination):
  - owner       : who is responsible for patching
  - status      : open | in_progress | mitigated | accepted_risk | resolved
  - due_date    : ISO date YYYY-MM-DD
  - notes       : free-text notes
  - accepted_by : reviewer name (for accepted_risk status)
  - accepted_on : ISO date of risk acceptance
  - expiry_date : ISO date when accepted_risk expires (re-surfaces in reports)
  - created_at  : unix timestamp
  - updated_at  : unix timestamp

Public API
----------
  get_item(db, cve_id, sw_name)               → dict | None
  upsert_item(db, cve_id, sw_name, **fields)  → None
  delete_item(db, cve_id, sw_name)            → None
  all_items(db)                               → List[dict]
  open_items(db)                              → List[dict]
  expired_acceptances(db)                     → List[dict]
  enrich_rows_with_remediation(db, rows)      → List[dict]
  remediation_summary(db)                     → dict
  export_remediation_csv(db, path)            → int
  import_remediation_csv(db, path)            → int
"""

import csv
import datetime
import sqlite3
import time
from typing import Any, Dict, List, Optional


# ------------------------------------------------------------------
# Status constants
# ------------------------------------------------------------------
STATUS_OPEN          = "open"
STATUS_IN_PROGRESS   = "in_progress"
STATUS_MITIGATED     = "mitigated"       # compensating control applied, not patched
STATUS_ACCEPTED_RISK = "accepted_risk"   # formally accepted, with optional expiry
STATUS_RESOLVED      = "resolved"        # patched / remediated

ALL_STATUSES = [
    STATUS_OPEN,
    STATUS_IN_PROGRESS,
    STATUS_MITIGATED,
    STATUS_ACCEPTED_RISK,
    STATUS_RESOLVED,
]

# SLA targets by CVSS severity (days to remediate)
DEFAULT_SLA_DAYS: Dict[str, int] = {
    "CRITICAL": 3,
    "HIGH":     7,
    "MEDIUM":   30,
    "LOW":      90,
}

# ------------------------------------------------------------------
# Schema
# ------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediation_items (
    cve_id        TEXT NOT NULL,
    sw_name       TEXT NOT NULL,
    owner         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open',
    due_date      TEXT NOT NULL DEFAULT '',     -- YYYY-MM-DD or ''
    notes         TEXT NOT NULL DEFAULT '',
    accepted_by   TEXT NOT NULL DEFAULT '',
    accepted_on   TEXT NOT NULL DEFAULT '',
    expiry_date   TEXT NOT NULL DEFAULT '',     -- YYYY-MM-DD or '' (for accepted_risk)
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL,
    PRIMARY KEY (cve_id, sw_name)
);
CREATE INDEX IF NOT EXISTS idx_rem_status   ON remediation_items(status);
CREATE INDEX IF NOT EXISTS idx_rem_due_date ON remediation_items(due_date);
CREATE INDEX IF NOT EXISTS idx_rem_owner    ON remediation_items(owner);
"""

_COLS = [
    "cve_id", "sw_name", "owner", "status", "due_date", "notes",
    "accepted_by", "accepted_on", "expiry_date", "created_at", "updated_at",
]


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(_SCHEMA)
    con.commit()


def _con(db: Any) -> sqlite3.Connection:
    """Extract a sqlite3.Connection from a DraugrDB instance or a bare connection."""
    if hasattr(db, "con"):
        return db.con
    return db


# ------------------------------------------------------------------
# CRUD
# ------------------------------------------------------------------
def get_item(db: Any, cve_id: str, sw_name: str) -> Optional[Dict[str, Any]]:
    """Return the remediation record for (cve_id, sw_name), or None."""
    con = _con(db)
    _ensure_schema(con)
    row = con.execute(
        "SELECT " + ", ".join(_COLS) + " FROM remediation_items WHERE cve_id=? AND sw_name=?",
        (cve_id.upper().strip(), sw_name.strip())
    ).fetchone()
    return dict(zip(_COLS, row)) if row else None


def upsert_item(
    db: Any,
    cve_id: str,
    sw_name: str,
    owner: str = "",
    status: str = STATUS_OPEN,
    due_date: str = "",
    notes: str = "",
    accepted_by: str = "",
    accepted_on: str = "",
    expiry_date: str = "",
) -> Dict[str, Any]:
    """
    Insert or update a remediation item.
    On update, only the explicitly supplied fields are changed.
    Returns the final item dict.
    """
    con = _con(db)
    _ensure_schema(con)
    cve_id  = cve_id.upper().strip()
    sw_name = sw_name.strip()

    if status not in ALL_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {ALL_STATUSES}")

    now = time.time()
    existing = get_item(db, cve_id, sw_name)

    if existing is None:
        con.execute(
            """INSERT INTO remediation_items
               (cve_id, sw_name, owner, status, due_date, notes,
                accepted_by, accepted_on, expiry_date, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (cve_id, sw_name, owner, status, due_date, notes,
             accepted_by, accepted_on, expiry_date, now, now)
        )
    else:
        # Merge: only overwrite with supplied values
        def _pick(new_val: str, old_key: str) -> str:
            return new_val if new_val != "" else existing[old_key]

        con.execute(
            """UPDATE remediation_items SET
               owner=?, status=?, due_date=?, notes=?,
               accepted_by=?, accepted_on=?, expiry_date=?, updated_at=?
               WHERE cve_id=? AND sw_name=?""",
            (
                _pick(owner,       "owner"),
                _pick(status,      "status") if status != STATUS_OPEN else existing["status"],
                _pick(due_date,    "due_date"),
                _pick(notes,       "notes"),
                _pick(accepted_by, "accepted_by"),
                _pick(accepted_on, "accepted_on"),
                _pick(expiry_date, "expiry_date"),
                now, cve_id, sw_name,
            )
        )
    con.commit()
    return get_item(db, cve_id, sw_name)


def delete_item(db: Any, cve_id: str, sw_name: str) -> None:
    """Remove a remediation record."""
    con = _con(db)
    con.execute(
        "DELETE FROM remediation_items WHERE cve_id=? AND sw_name=?",
        (cve_id.upper().strip(), sw_name.strip())
    )
    con.commit()


def all_items(db: Any) -> List[Dict[str, Any]]:
    """Return all remediation items, newest updated first."""
    con = _con(db)
    _ensure_schema(con)
    rows = con.execute(
        "SELECT " + ", ".join(_COLS) + " FROM remediation_items ORDER BY updated_at DESC"
    ).fetchall()
    return [dict(zip(_COLS, r)) for r in rows]


def open_items(db: Any) -> List[Dict[str, Any]]:
    """Return all items that are not resolved."""
    con = _con(db)
    _ensure_schema(con)
    rows = con.execute(
        "SELECT " + ", ".join(_COLS) + " FROM remediation_items "
        "WHERE status != ? ORDER BY due_date ASC, updated_at DESC",
        (STATUS_RESOLVED,)
    ).fetchall()
    return [dict(zip(_COLS, r)) for r in rows]


def overdue_items(db: Any) -> List[Dict[str, Any]]:
    """Return open items whose due_date has passed."""
    today = datetime.date.today().isoformat()
    con   = _con(db)
    _ensure_schema(con)
    rows  = con.execute(
        "SELECT " + ", ".join(_COLS) + " FROM remediation_items "
        "WHERE status NOT IN (?, ?) AND due_date != '' AND due_date < ? "
        "ORDER BY due_date ASC",
        (STATUS_RESOLVED, STATUS_ACCEPTED_RISK, today)
    ).fetchall()
    return [dict(zip(_COLS, r)) for r in rows]


def expired_acceptances(db: Any) -> List[Dict[str, Any]]:
    """
    Return accepted_risk items whose expiry_date has passed.
    These should be re-reviewed — they surface in reports as needing attention.
    """
    today = datetime.date.today().isoformat()
    con   = _con(db)
    _ensure_schema(con)
    rows  = con.execute(
        "SELECT " + ", ".join(_COLS) + " FROM remediation_items "
        "WHERE status=? AND expiry_date != '' AND expiry_date < ? "
        "ORDER BY expiry_date ASC",
        (STATUS_ACCEPTED_RISK, today)
    ).fetchall()
    return [dict(zip(_COLS, r)) for r in rows]


# ------------------------------------------------------------------
# Scan row enrichment
# ------------------------------------------------------------------
def enrich_rows_with_remediation(
    db: Any,
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Add remediation fields to scan row dicts in-place.

    Added fields per row:
      Remediation Status   — open | in_progress | mitigated | accepted_risk | resolved
      Remediation Owner    — assigned owner
      Remediation Due Date — YYYY-MM-DD
      Remediation Notes    — free-text
      Acceptance Expired   — Yes if accepted_risk and expiry_date has passed
    """
    con = _con(db)
    _ensure_schema(con)

    # Build lookup: (cve_id, sw_name) → item
    all_rem = {
        (r["cve_id"], r["sw_name"]): r
        for r in all_items(db)
    }
    today = datetime.date.today().isoformat()

    for row in rows:
        cid  = str(row.get("CVE ID",       "") or "").upper().strip()
        name = str(row.get("Software Name", "") or "").strip()
        item = all_rem.get((cid, name))

        if item:
            row["Remediation Status"]   = item["status"]
            row["Remediation Owner"]    = item["owner"]
            row["Remediation Due Date"] = item["due_date"]
            row["Remediation Notes"]    = item["notes"]
            # Flag expired acceptances so they surface visually
            expired = (
                item["status"] == STATUS_ACCEPTED_RISK
                and item["expiry_date"]
                and item["expiry_date"] < today
            )
            row["Acceptance Expired"] = "Yes" if expired else ""
        else:
            row["Remediation Status"]   = STATUS_OPEN
            row["Remediation Owner"]    = ""
            row["Remediation Due Date"] = ""
            row["Remediation Notes"]    = ""
            row["Acceptance Expired"]   = ""

    return rows


def suggest_due_date(severity: str, from_date: Optional[datetime.date] = None) -> str:
    """
    Return a suggested due date string (YYYY-MM-DD) based on CVSS severity
    and the DEFAULT_SLA_DAYS targets.
    """
    base  = from_date or datetime.date.today()
    days  = DEFAULT_SLA_DAYS.get(severity.upper(), 30)
    due   = base + datetime.timedelta(days=days)
    return due.isoformat()


# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
def remediation_summary(db: Any) -> Dict[str, Any]:
    """
    Return counts by status plus overdue and expired-acceptance counts.
    Suitable for dashboard widgets and report sections.
    """
    con = _con(db)
    _ensure_schema(con)

    counts: Dict[str, int] = {s: 0 for s in ALL_STATUSES}
    rows = con.execute(
        "SELECT status, COUNT(*) FROM remediation_items GROUP BY status"
    ).fetchall()
    for status, cnt in rows:
        if status in counts:
            counts[status] = cnt

    total    = sum(counts.values())
    overdue  = len(overdue_items(db))
    expired  = len(expired_acceptances(db))

    return {
        "total":           total,
        "by_status":       counts,
        "overdue":         overdue,
        "expired_waivers": expired,
        "open_total":      total - counts[STATUS_RESOLVED],
    }


# ------------------------------------------------------------------
# Import / Export
# ------------------------------------------------------------------
_CSV_FIELDS = [
    "cve_id", "sw_name", "owner", "status", "due_date",
    "notes", "accepted_by", "accepted_on", "expiry_date",
]


def export_remediation_csv(db: Any, path: str) -> int:
    """
    Export all remediation items to a CSV file.
    Returns count of rows written.
    """
    items = all_items(db)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(items)
    return len(items)


def import_remediation_csv(db: Any, path: str) -> int:
    """
    Import remediation items from a CSV file, upserting each row.
    Returns count of rows imported.
    """
    count = 0
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id  = str(row.get("cve_id",  "") or "").strip()
            sw_name = str(row.get("sw_name", "") or "").strip()
            if not cve_id or not sw_name:
                continue
            upsert_item(
                db,
                cve_id=cve_id,
                sw_name=sw_name,
                owner=str(row.get("owner",       "") or ""),
                status=str(row.get("status",      STATUS_OPEN) or STATUS_OPEN),
                due_date=str(row.get("due_date",  "") or ""),
                notes=str(row.get("notes",        "") or ""),
                accepted_by=str(row.get("accepted_by",  "") or ""),
                accepted_on=str(row.get("accepted_on",  "") or ""),
                expiry_date=str(row.get("expiry_date",  "") or ""),
            )
            count += 1
    return count


# ------------------------------------------------------------------
# Report section (markdown)
# ------------------------------------------------------------------
def remediation_report_section(db: Any) -> str:
    """
    Return a markdown section summarising remediation state.
    Intended to be appended to Draugr reports.
    """
    summary = remediation_summary(db)
    if summary["total"] == 0:
        return ""

    by_status = summary["by_status"]
    lines = [
        "## Remediation Tracking",
        "",
        f"**{summary['total']}** finding(s) tracked | "
        f"**{summary['open_total']}** open | "
        f"**{by_status[STATUS_RESOLVED]}** resolved",
        "",
        "| Status | Count |",
        "|---|---|",
    ]
    labels = {
        STATUS_OPEN:          "Open",
        STATUS_IN_PROGRESS:   "In Progress",
        STATUS_MITIGATED:     "Mitigated (Compensating Control)",
        STATUS_ACCEPTED_RISK: "Accepted Risk",
        STATUS_RESOLVED:      "Resolved",
    }
    for status in ALL_STATUSES:
        cnt = by_status.get(status, 0)
        lines.append(f"| {labels[status]} | {cnt} |")

    lines.append("")

    if summary["overdue"] > 0:
        lines.append(
            f"> ⚠ **{summary['overdue']} overdue item(s)** — due dates have passed "
            "and findings are not yet resolved. Escalation required."
        )
        lines.append("")

    if summary["expired_waivers"] > 0:
        lines.append(
            f"> 🔁 **{summary['expired_waivers']} risk acceptance(s) expired** — "
            "these findings were previously accepted but the waiver period has lapsed. "
            "Re-review required."
        )
        lines.append("")

    # List overdue items
    overdue = overdue_items(db)
    if overdue:
        lines += [
            "### Overdue Findings",
            "",
            "| CVE | Software | Owner | Due | Status |",
            "|---|---|---|---|---|",
        ]
        for item in overdue[:20]:
            lines.append(
                f"| {item['cve_id']} | {item['sw_name']} | "
                f"{item['owner'] or '—'} | {item['due_date']} | {item['status']} |"
            )
        if len(overdue) > 20:
            lines.append(f"\n_...and {len(overdue) - 20} more overdue item(s)._")
        lines.append("")

    return "\n".join(lines)
