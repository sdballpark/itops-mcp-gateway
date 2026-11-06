"""
Audit log and approval queue.

THE AUDIT LOG
-------------
Append only. No code path issues UPDATE or DELETE against the audit_log table, and
'modify_audit_log' appears in NEVER_EXPOSED so no tool can reach it either.

Every tool invocation is logged whether it succeeded, was denied, or errored.
Denials matter more than successes: a run of denied privileged calls is the signal
that either an agent is misconfigured or someone is probing what it can reach.

Arguments are redacted before they are written. The log has to prove what happened
without becoming a second place secrets accumulate.

THE APPROVAL QUEUE
------------------
A privileged tool call does not execute. It returns an approval_id and stops. A human
then approves or denies out of band, and only on approval does the action run.

The agent cannot approve its own request. That is enforced by the approval endpoint
living outside the MCP tool surface entirely: there is no 'approve' tool, so no
sequence of model outputs can reach it. An operator uses the HTTP API or the CLI.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import Decision, Tier, redact


# The gateway owns these two tables. They are created here, not by any seed script,
# so a Gateway built on a fresh database works on its first call whatever policy it
# runs. CREATE ... IF NOT EXISTS leaves an existing table and its history untouched.
AUDIT_SCHEMA = """
-- Append-only. No code path issues UPDATE or DELETE against this table.
CREATE TABLE IF NOT EXISTS audit_log (
    entry_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    client_role  TEXT NOT NULL,
    tool_name    TEXT NOT NULL,
    tier         TEXT NOT NULL,
    decision     TEXT NOT NULL,
    reason       TEXT,
    arguments    TEXT NOT NULL,
    result_summary TEXT,
    duration_ms  REAL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool_name);
"""

APPROVALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    approval_id    TEXT PRIMARY KEY,
    tool_name      TEXT NOT NULL,
    arguments      TEXT NOT NULL,
    requested_by   TEXT NOT NULL,
    requested_at   TEXT NOT NULL,
    justification  TEXT NOT NULL,
    status         TEXT NOT NULL,
    decided_by     TEXT,
    decided_at     TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    def __init__(self, db_path: str | Path = "data/itops.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(AUDIT_SCHEMA)

    def record(
        self,
        client_id: str,
        client_role: str,
        tool_name: str,
        tier: Tier,
        decision: Decision,
        arguments: dict[str, Any],
        reason: str | None = None,
        result_summary: str | None = None,
        duration_ms: float | None = None,
    ) -> int:
        safe_args = json.dumps(redact(arguments), separators=(",", ":"))[:4000]
        cur = self._conn.execute(
            "INSERT INTO audit_log (timestamp, client_id, client_role, tool_name, tier,"
            " decision, reason, arguments, result_summary, duration_ms)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (_now(), client_id, client_role, tool_name, tier.value, decision.value,
             reason, safe_args, (result_summary or "")[:500], duration_ms),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def tail(self, limit: int = 25) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY entry_id DESC LIMIT ?", (int(limit),)
        ).fetchall()
        return [dict(r) for r in rows]

    def summary(self) -> dict[str, Any]:
        """Aggregates an operator would actually watch."""
        total = self._conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
        by_decision = {
            r["decision"]: r["c"]
            for r in self._conn.execute(
                "SELECT decision, COUNT(*) c FROM audit_log GROUP BY decision"
            ).fetchall()
        }
        by_tier = {
            r["tier"]: r["c"]
            for r in self._conn.execute(
                "SELECT tier, COUNT(*) c FROM audit_log GROUP BY tier"
            ).fetchall()
        }
        top_tools = [
            {"tool": r["tool_name"], "calls": r["c"]}
            for r in self._conn.execute(
                "SELECT tool_name, COUNT(*) c FROM audit_log GROUP BY tool_name "
                "ORDER BY c DESC LIMIT 8"
            ).fetchall()
        ]
        denied = [
            dict(r) for r in self._conn.execute(
                "SELECT timestamp, client_role, tool_name, reason FROM audit_log "
                "WHERE decision = 'deny' ORDER BY entry_id DESC LIMIT 10"
            ).fetchall()
        ]
        return {
            "total_calls": total,
            "by_decision": by_decision,
            "by_tier": by_tier,
            "top_tools": top_tools,
            "recent_denials": denied,
        }

    def close(self) -> None:
        self._conn.close()


class ApprovalQueue:
    def __init__(self, db_path: str | Path = "data/itops.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(APPROVALS_SCHEMA)

    def create(self, tool_name: str, arguments: dict[str, Any],
               requested_by: str, justification: str) -> dict[str, Any]:
        approval_id = f"APR-{uuid.uuid4().hex[:12]}"
        self._conn.execute(
            "INSERT INTO approvals (approval_id, tool_name, arguments, requested_by,"
            " requested_at, justification, status) VALUES (?,?,?,?,?,?,?)",
            (approval_id, tool_name, json.dumps(redact(arguments)), requested_by,
             _now(), justification, "pending"),
        )
        self._conn.commit()
        # The unredacted arguments are held in memory only for the pending execution.
        self._pending_args = getattr(self, "_pending_args", {})
        self._pending_args[approval_id] = arguments
        return {
            "approval_id": approval_id,
            "status": "pending",
            "tool_name": tool_name,
            "requested_at": _now(),
            "message": ("This action changes entitlements and was NOT executed. "
                        "A human must approve it. The requesting agent cannot approve "
                        "its own request."),
        }

    def get(self, approval_id: str) -> dict[str, Any] | None:
        r = self._conn.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        return dict(r) if r else None

    def pending(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE status = 'pending' ORDER BY requested_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def arguments_for(self, approval_id: str) -> dict[str, Any] | None:
        return getattr(self, "_pending_args", {}).get(approval_id)

    def decide(self, approval_id: str, approved: bool, decided_by: str) -> dict[str, Any]:
        rec = self.get(approval_id)
        if rec is None:
            return {"ok": False, "error": f"unknown approval_id: {approval_id}"}
        if rec["status"] != "pending":
            return {"ok": False, "error": f"approval already {rec['status']}"}
        if not decided_by or decided_by.strip().lower().endswith("_agent"):
            # Belt and braces: the endpoint is already outside the tool surface.
            return {"ok": False, "error": "approvals require a human approver identity"}
        status = "approved" if approved else "denied"
        self._conn.execute(
            "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? "
            "WHERE approval_id = ?",
            (status, decided_by, _now(), approval_id),
        )
        self._conn.commit()
        return {"ok": True, "approval_id": approval_id, "status": status,
                "decided_by": decided_by}

    def mark_executed(self, approval_id: str) -> None:
        self._conn.execute(
            "UPDATE approvals SET status = 'executed' WHERE approval_id = ?", (approval_id,)
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
