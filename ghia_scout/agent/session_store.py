"""Session persistence: save/resume long engagements and diff scans over time."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ghia_scout.config.settings import SESSIONS_DIR, ensure_dirs

_DB_PATH: Path | None = None


def _db() -> sqlite3.Connection:
    global _DB_PATH
    ensure_dirs()
    if _DB_PATH is None:
        _DB_PATH = SESSIONS_DIR / "sessions.db"
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        target      TEXT NOT NULL,
        created_at  REAL NOT NULL,
        updated_at  REAL NOT NULL,
        status      TEXT NOT NULL DEFAULT 'active',
        label       TEXT,
        notes       TEXT,
        state_json  TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target);
    CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

    CREATE TABLE IF NOT EXISTS session_snapshots (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  TEXT NOT NULL REFERENCES sessions(id),
        taken_at    REAL NOT NULL,
        step        INTEGER NOT NULL DEFAULT 0,
        snapshot_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS session_findings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  TEXT NOT NULL REFERENCES sessions(id),
        found_at    REAL NOT NULL,
        severity    TEXT,
        title       TEXT,
        detail      TEXT,
        cvss        REAL,
        cve         TEXT
    );
    """)
    conn.commit()


# ── Public API ────────────────────────────────────────────────────────


@dataclass
class SessionRecord:
    id: str
    target: str
    created_at: float
    updated_at: float
    status: str = "active"
    label: str = ""
    notes: str = ""
    state: dict[str, Any] = field(default_factory=dict)


def create_session(target: str, label: str = "", notes: str = "") -> str:
    """Create a new session and return its ID."""
    import uuid
    sid = str(uuid.uuid4())[:8]
    now = time.time()
    conn = _db()
    conn.execute(
        "INSERT INTO sessions (id, target, created_at, updated_at, status, label, notes, state_json) "
        "VALUES (?, ?, ?, ?, 'active', ?, ?, '{}')",
        (sid, target, now, now, label, notes),
    )
    conn.commit()
    conn.close()
    return sid


def load_session(session_id: str) -> SessionRecord | None:
    conn = _db()
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return SessionRecord(
        id=row["id"],
        target=row["target"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        status=row["status"],
        label=row["label"] or "",
        notes=row["notes"] or "",
        state=json.loads(row["state_json"] or "{}"),
    )


def save_session_state(session_id: str, state: dict[str, Any]) -> None:
    now = time.time()
    conn = _db()
    conn.execute(
        "UPDATE sessions SET state_json = ?, updated_at = ? WHERE id = ?",
        (json.dumps(state, default=str), now, session_id),
    )
    conn.commit()
    conn.close()


def close_session(session_id: str, status: str = "completed") -> None:
    conn = _db()
    conn.execute(
        "UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?",
        (status, time.time(), session_id),
    )
    conn.commit()
    conn.close()


def list_sessions(target: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    conn = _db()
    if target:
        rows = conn.execute(
            "SELECT id, target, created_at, updated_at, status, label FROM sessions "
            "WHERE target = ? ORDER BY updated_at DESC LIMIT ?",
            (target, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, target, created_at, updated_at, status, label FROM sessions "
            "ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "target": r["target"],
            "created_at": datetime.fromtimestamp(r["created_at"]).isoformat(),
            "updated_at": datetime.fromtimestamp(r["updated_at"]).isoformat(),
            "status": r["status"],
            "label": r["label"] or "",
        }
        for r in rows
    ]


# ── Snapshots (checkpoint within a session) ───────────────────────────


def take_snapshot(session_id: str, step: int, snapshot: dict[str, Any]) -> None:
    conn = _db()
    conn.execute(
        "INSERT INTO session_snapshots (session_id, taken_at, step, snapshot_json) VALUES (?, ?, ?, ?)",
        (session_id, time.time(), step, json.dumps(snapshot, default=str)),
    )
    conn.commit()
    conn.close()


def list_snapshots(session_id: str) -> list[dict[str, Any]]:
    conn = _db()
    rows = conn.execute(
        "SELECT id, taken_at, step FROM session_snapshots WHERE session_id = ? ORDER BY step",
        (session_id,),
    ).fetchall()
    conn.close()
    return [
        {"snap_id": r["id"], "step": r["step"],
         "taken_at": datetime.fromtimestamp(r["taken_at"]).isoformat()}
        for r in rows
    ]


def load_snapshot(snap_id: int) -> dict[str, Any]:
    conn = _db()
    row = conn.execute("SELECT snapshot_json FROM session_snapshots WHERE id = ?", (snap_id,)).fetchone()
    conn.close()
    return json.loads(row["snapshot_json"]) if row else {}


# ── Findings log ──────────────────────────────────────────────────────


def log_finding(
    session_id: str,
    title: str,
    severity: str = "medium",
    detail: str = "",
    cvss: float | None = None,
    cve: str = "",
) -> None:
    conn = _db()
    conn.execute(
        "INSERT INTO session_findings (session_id, found_at, severity, title, detail, cvss, cve) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session_id, time.time(), severity, title, detail, cvss, cve),
    )
    conn.commit()
    conn.close()


def get_findings(session_id: str) -> list[dict[str, Any]]:
    conn = _db()
    rows = conn.execute(
        "SELECT found_at, severity, title, detail, cvss, cve FROM session_findings "
        "WHERE session_id = ? ORDER BY found_at",
        (session_id,),
    ).fetchall()
    conn.close()
    return [
        {
            "found_at": datetime.fromtimestamp(r["found_at"]).isoformat(),
            "severity": r["severity"],
            "title": r["title"],
            "detail": r["detail"] or "",
            "cvss": r["cvss"],
            "cve": r["cve"] or "",
        }
        for r in rows
    ]


# ── Diff two sessions ─────────────────────────────────────────────────


def diff_sessions(session_a: str, session_b: str) -> dict[str, Any]:
    """Compare findings between two sessions on the same target."""
    fa = {f["title"]: f for f in get_findings(session_a)}
    fb = {f["title"]: f for f in get_findings(session_b)}

    new_in_b = [fb[t] for t in fb if t not in fa]
    fixed_in_b = [fa[t] for t in fa if t not in fb]
    common_titles = [t for t in fb if t in fa]
    severity_changed = [
        {"title": t, "before": fa[t]["severity"], "after": fb[t]["severity"]}
        for t in common_titles
        if fa[t]["severity"] != fb[t]["severity"]
    ]
    changed_titles = {s["title"] for s in severity_changed}

    return {
        "new_findings": new_in_b,
        "fixed_findings": fixed_in_b,
        "severity_changes": severity_changed,
        "unchanged": [t for t in common_titles if t not in changed_titles],
    }


# ── Tool wrappers (agent-callable) ────────────────────────────────────

SESSION_STORE_TOOLS: dict[str, Any] = {
    "session_save": {
        "description": "Save current engagement state so it can be resumed later",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "label": {"type": "string"},
                "notes": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    "session_resume": {
        "description": "Resume a previous engagement by ID and restore its state",
        "parameters": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    "session_list": {
        "description": "List saved engagement sessions",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
            },
        },
    },
    "session_diff": {
        "description": "Compare findings between two sessions to see what was fixed or newly found",
        "parameters": {
            "type": "object",
            "properties": {
                "session_a": {"type": "string"},
                "session_b": {"type": "string"},
            },
            "required": ["session_a", "session_b"],
        },
    },
}


async def dispatch_session_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name == "session_save":
        sid = create_session(args["target"], args.get("label", ""), args.get("notes", ""))
        state = {}
        if hasattr(agent, "session") and agent.session:
            try:
                state = {
                    "target": getattr(agent.session, "target", ""),
                    "step": getattr(agent.session, "step_count", 0),
                    "findings": len(getattr(agent.session, "findings", [])),
                }
            except Exception:
                pass
        save_session_state(sid, state)
        return f"[session_save] Created session {sid} for target {args['target']}"

    if tool_name == "session_resume":
        rec = load_session(args["session_id"])
        if not rec:
            return f"[session_resume] Session {args['session_id']} not found"
        snaps = list_snapshots(rec.id)
        findings = get_findings(rec.id)
        return (
            f"[session_resume] Session {rec.id}\n"
            f"  Target: {rec.target}\n"
            f"  Status: {rec.status}\n"
            f"  Created: {datetime.fromtimestamp(rec.created_at).isoformat()}\n"
            f"  Snapshots: {len(snaps)}\n"
            f"  Findings: {len(findings)}\n"
            f"  State keys: {list(rec.state.keys())}"
        )

    if tool_name == "session_list":
        sessions = list_sessions(args.get("target"), args.get("limit", 10))
        if not sessions:
            return "[session_list] No sessions found"
        lines = ["[session_list]"]
        for s in sessions:
            lines.append(f"  {s['id']} | {s['target']} | {s['status']} | {s['updated_at']}")
        return "\n".join(lines)

    if tool_name == "session_diff":
        diff = diff_sessions(args["session_a"], args["session_b"])
        lines = [f"[session_diff] {args['session_a']} vs {args['session_b']}"]
        lines.append(f"  New findings: {len(diff['new_findings'])}")
        for f in diff["new_findings"][:5]:
            lines.append(f"    + [{f['severity']}] {f['title']}")
        lines.append(f"  Fixed findings: {len(diff['fixed_findings'])}")
        for f in diff["fixed_findings"][:5]:
            lines.append(f"    - [{f['severity']}] {f['title']}")
        lines.append(f"  Severity changes: {len(diff['severity_changes'])}")
        for sc in diff["severity_changes"]:
            lines.append(f"    ~ {sc['title']}: {sc['before']} → {sc['after']}")
        return "\n".join(lines)

    return None
