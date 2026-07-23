"""
Backend interface and implementations.

WHY THIS BOUNDARY EXISTS
------------------------
The point of an MCP gateway is that the agent never talks to ServiceNow or Entra ID
directly. It calls a tool on this server, and this server decides what to do. All the
interesting engineering - tool schemas, permission tiers, approval gates, audit
logging, validation - lives above this interface and is independent of what sits
below it.

That makes the backend swappable. The demo runs on SQLite so the repository is
self-contained and starts anywhere with no credentials. Pointing it at a real
ServiceNow instance or Entra ID tenant means implementing this same interface, and
nothing in the security layer changes.

The stubs at the bottom are not dead code. They document exactly which API calls each
production backend would make, which is the part worth reviewing.
"""
from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Domain types
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class User:
    user_id: str
    display_name: str
    email: str
    department: str
    manager_id: str | None
    status: str          # active | disabled | suspended
    mfa_enrolled: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "display_name": self.display_name,
            "email": self.email,
            "department": self.department,
            "manager_id": self.manager_id,
            "status": self.status,
            "mfa_enrolled": self.mfa_enrolled,
        }


@dataclass(frozen=True)
class Group:
    group_id: str
    name: str
    description: str
    privileged: bool     # membership grants elevated access

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "description": self.description,
            "privileged": self.privileged,
        }


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    title: str
    description: str
    status: str          # new | in_progress | pending | resolved | closed
    priority: str        # low | medium | high | critical
    category: str
    requester_id: str
    assignee_id: str | None
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "priority": self.priority,
            "category": self.category,
            "requester_id": self.requester_id,
            "assignee_id": self.assignee_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class ApprovalRequest:
    approval_id: str
    tool_name: str
    arguments: dict[str, Any]
    requested_by: str
    requested_at: str
    justification: str
    status: str = "pending"          # pending | approved | denied | executed
    decided_by: str | None = None
    decided_at: str | None = None
    result: dict[str, Any] | None = field(default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "justification": self.justification,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
        }


# --------------------------------------------------------------------------
# Interface
# --------------------------------------------------------------------------

class Backend(ABC):
    """Everything the tool layer needs from a system of record.

    Deliberately narrow. If a method does not appear here, no tool can reach it,
    which is a containment property rather than an oversight. Offboarding and
    account deletion are absent by design, not because they were forgotten.
    """

    # ---- identity: read ----
    @abstractmethod
    def find_user(self, query: str) -> list[User]: ...

    @abstractmethod
    def get_user(self, user_id: str) -> User | None: ...

    @abstractmethod
    def list_user_groups(self, user_id: str) -> list[Group]: ...

    @abstractmethod
    def list_groups(self) -> list[Group]: ...

    # ---- identity: privileged write ----
    @abstractmethod
    def add_user_to_group(self, user_id: str, group_id: str) -> dict[str, Any]: ...

    # ---- itsm: read ----
    @abstractmethod
    def search_tickets(self, query: str | None, status: str | None, limit: int) -> list[Ticket]: ...

    @abstractmethod
    def get_ticket(self, ticket_id: str) -> Ticket | None: ...

    @abstractmethod
    def get_ticket_comments(self, ticket_id: str) -> list[dict[str, Any]]: ...

    # ---- itsm: write ----
    @abstractmethod
    def create_ticket(self, title: str, description: str, priority: str,
                      category: str, requester_id: str) -> Ticket: ...

    @abstractmethod
    def add_comment(self, ticket_id: str, author: str, body: str) -> dict[str, Any]: ...

    @abstractmethod
    def update_ticket_status(self, ticket_id: str, status: str) -> Ticket: ...

    # ---- knowledge ----
    @abstractmethod
    def search_knowledge(self, query: str, limit: int) -> list[dict[str, Any]]: ...


# --------------------------------------------------------------------------
# SQLite implementation
# --------------------------------------------------------------------------

class SQLiteBackend(Backend):
    """Local implementation used by the demo and the test suite.

    Every query is parameterised. That is the actual defence against injection
    through tool arguments; the validation layer above is defence in depth, not the
    primary control. An LLM will happily pass a quote character into a search string
    and it must not matter.
    """

    def __init__(self, db_path: str | Path = "data/itops.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")

    # -- helpers --
    def _q(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self._conn.execute(sql, params).fetchall()

    def _exec(self, sql: str, params: tuple = ()) -> None:
        self._conn.execute(sql, params)
        self._conn.commit()

    @staticmethod
    def _user(r: sqlite3.Row) -> User:
        return User(r["user_id"], r["display_name"], r["email"], r["department"],
                    r["manager_id"], r["status"], bool(r["mfa_enrolled"]))

    @staticmethod
    def _group(r: sqlite3.Row) -> Group:
        return Group(r["group_id"], r["name"], r["description"], bool(r["privileged"]))

    @staticmethod
    def _ticket(r: sqlite3.Row) -> Ticket:
        return Ticket(r["ticket_id"], r["title"], r["description"], r["status"],
                      r["priority"], r["category"], r["requester_id"],
                      r["assignee_id"], r["created_at"], r["updated_at"])

    # -- identity read --
    def find_user(self, query: str) -> list[User]:
        like = f"%{query}%"
        rows = self._q(
            "SELECT * FROM users WHERE display_name LIKE ? OR email LIKE ? OR user_id LIKE ? "
            "ORDER BY display_name LIMIT 25",
            (like, like, like),
        )
        return [self._user(r) for r in rows]

    def get_user(self, user_id: str) -> User | None:
        rows = self._q("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return self._user(rows[0]) if rows else None

    def list_user_groups(self, user_id: str) -> list[Group]:
        rows = self._q(
            "SELECT g.* FROM groups g JOIN memberships m ON g.group_id = m.group_id "
            "WHERE m.user_id = ? ORDER BY g.name",
            (user_id,),
        )
        return [self._group(r) for r in rows]

    def list_groups(self) -> list[Group]:
        return [self._group(r) for r in self._q("SELECT * FROM groups ORDER BY name")]

    # -- identity privileged write --
    def add_user_to_group(self, user_id: str, group_id: str) -> dict[str, Any]:
        if not self.get_user(user_id):
            return {"ok": False, "error": f"unknown user_id: {user_id}"}
        grp = self._q("SELECT * FROM groups WHERE group_id = ?", (group_id,))
        if not grp:
            return {"ok": False, "error": f"unknown group_id: {group_id}"}
        existing = self._q(
            "SELECT 1 FROM memberships WHERE user_id = ? AND group_id = ?", (user_id, group_id)
        )
        if existing:
            return {"ok": True, "changed": False, "detail": "already a member"}
        self._exec("INSERT INTO memberships (user_id, group_id) VALUES (?, ?)", (user_id, group_id))
        return {"ok": True, "changed": True, "user_id": user_id,
                "group_id": group_id, "group_name": grp[0]["name"]}

    # -- itsm read --
    def search_tickets(self, query: str | None, status: str | None, limit: int) -> list[Ticket]:
        sql = "SELECT * FROM tickets WHERE 1=1"
        params: list[Any] = []
        if query:
            sql += " AND (title LIKE ? OR description LIKE ?)"
            params += [f"%{query}%", f"%{query}%"]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(int(limit))
        return [self._ticket(r) for r in self._q(sql, tuple(params))]

    def get_ticket(self, ticket_id: str) -> Ticket | None:
        rows = self._q("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,))
        return self._ticket(rows[0]) if rows else None

    def get_ticket_comments(self, ticket_id: str) -> list[dict[str, Any]]:
        rows = self._q(
            "SELECT author, body, created_at FROM comments WHERE ticket_id = ? ORDER BY created_at",
            (ticket_id,),
        )
        return [dict(r) for r in rows]

    # -- itsm write --
    def create_ticket(self, title: str, description: str, priority: str,
                      category: str, requester_id: str) -> Ticket:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        n = self._q("SELECT COUNT(*) AS c FROM tickets")[0]["c"]
        tid = f"INC{100000 + n + 1}"
        self._exec(
            "INSERT INTO tickets (ticket_id, title, description, status, priority, category,"
            " requester_id, assignee_id, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (tid, title, description, "new", priority, category, requester_id, None, now, now),
        )
        created = self.get_ticket(tid)
        assert created is not None
        return created

    def add_comment(self, ticket_id: str, author: str, body: str) -> dict[str, Any]:
        from datetime import datetime, timezone
        if not self.get_ticket(ticket_id):
            return {"ok": False, "error": f"unknown ticket_id: {ticket_id}"}
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._exec(
            "INSERT INTO comments (ticket_id, author, body, created_at) VALUES (?,?,?,?)",
            (ticket_id, author, body, now),
        )
        self._exec("UPDATE tickets SET updated_at = ? WHERE ticket_id = ?", (now, ticket_id))
        return {"ok": True, "ticket_id": ticket_id, "created_at": now}

    def update_ticket_status(self, ticket_id: str, status: str) -> Ticket:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._exec(
            "UPDATE tickets SET status = ?, updated_at = ? WHERE ticket_id = ?",
            (status, now, ticket_id),
        )
        t = self.get_ticket(ticket_id)
        if t is None:
            raise ValueError(f"unknown ticket_id: {ticket_id}")
        return t

    # -- knowledge --
    def search_knowledge(self, query: str, limit: int) -> list[dict[str, Any]]:
        like = f"%{query}%"
        rows = self._q(
            "SELECT article_id, title, summary, category FROM kb_articles "
            "WHERE title LIKE ? OR summary LIKE ? OR body LIKE ? LIMIT ?",
            (like, like, like, int(limit)),
        )
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()


# --------------------------------------------------------------------------
# Production stubs
# --------------------------------------------------------------------------

class ServiceNowBackend(Backend):
    """ITSM backend against a real ServiceNow instance.

    Not implemented here because the demo must run with no credentials, but the
    mapping is mechanical and worth stating explicitly:

        search_tickets       GET  /api/now/table/incident?sysparm_query=...
        get_ticket           GET  /api/now/table/incident/{sys_id}
        create_ticket        POST /api/now/table/incident
        add_comment          PATCH /api/now/table/incident/{sys_id}  (work_notes)
        update_ticket_status PATCH /api/now/table/incident/{sys_id}  (state)
        search_knowledge     GET  /api/now/table/kb_knowledge?sysparm_query=...

    Auth is OAuth 2.0 client credentials against the instance, token cached and
    refreshed ahead of expiry, secret held in a vault rather than environment
    variables. The service account is scoped to the incident and kb tables only, so
    a compromise of this gateway cannot reach CMDB or change management.
    """

    def __init__(self, instance_url: str, oauth_token_provider: Any):
        self.instance_url = instance_url
        self._token_provider = oauth_token_provider

    def _not_implemented(self, name: str):
        raise NotImplementedError(
            f"ServiceNowBackend.{name} is a documented stub. "
            "The demo runs on SQLiteBackend; see docs/DESIGN_NOTES.md."
        )

    def find_user(self, query): self._not_implemented("find_user")
    def get_user(self, user_id): self._not_implemented("get_user")
    def list_user_groups(self, user_id): self._not_implemented("list_user_groups")
    def list_groups(self): self._not_implemented("list_groups")
    def add_user_to_group(self, user_id, group_id): self._not_implemented("add_user_to_group")
    def search_tickets(self, query, status, limit): self._not_implemented("search_tickets")
    def get_ticket(self, ticket_id): self._not_implemented("get_ticket")
    def get_ticket_comments(self, ticket_id): self._not_implemented("get_ticket_comments")
    def create_ticket(self, title, description, priority, category, requester_id):
        self._not_implemented("create_ticket")
    def add_comment(self, ticket_id, author, body): self._not_implemented("add_comment")
    def update_ticket_status(self, ticket_id, status): self._not_implemented("update_ticket_status")
    def search_knowledge(self, query, limit): self._not_implemented("search_knowledge")


class EntraIDBackend(Backend):
    """Identity backend against Microsoft Entra ID via Graph.

        find_user           GET  /v1.0/users?$search="displayName:..."
        get_user            GET  /v1.0/users/{id}
        list_user_groups    GET  /v1.0/users/{id}/memberOf
        list_groups         GET  /v1.0/groups
        add_user_to_group   POST /v1.0/groups/{id}/members/$ref

    Auth is client credentials with a certificate rather than a client secret.
    Graph permissions are the narrowest that work: User.Read.All and
    GroupMember.ReadWrite.All. Notably NOT Directory.ReadWrite.All, which would
    also permit account deletion and role assignment. The permission gradient in
    src/security.py is enforced a second time here, at the API scope, so a bug in
    the gateway cannot grant the agent capabilities the token does not carry.

    Anything privileged routes through PIM for just-in-time elevation rather than
    standing access.
    """

    def __init__(self, tenant_id: str, client_id: str, credential_provider: Any):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self._credential = credential_provider

    def _not_implemented(self, name: str):
        raise NotImplementedError(
            f"EntraIDBackend.{name} is a documented stub. "
            "The demo runs on SQLiteBackend; see docs/DESIGN_NOTES.md."
        )

    def find_user(self, query): self._not_implemented("find_user")
    def get_user(self, user_id): self._not_implemented("get_user")
    def list_user_groups(self, user_id): self._not_implemented("list_user_groups")
    def list_groups(self): self._not_implemented("list_groups")
    def add_user_to_group(self, user_id, group_id): self._not_implemented("add_user_to_group")
    def search_tickets(self, query, status, limit): self._not_implemented("search_tickets")
    def get_ticket(self, ticket_id): self._not_implemented("get_ticket")
    def get_ticket_comments(self, ticket_id): self._not_implemented("get_ticket_comments")
    def create_ticket(self, title, description, priority, category, requester_id):
        self._not_implemented("create_ticket")
    def add_comment(self, ticket_id, author, body): self._not_implemented("add_comment")
    def update_ticket_status(self, ticket_id, status): self._not_implemented("update_ticket_status")
    def search_knowledge(self, query, limit): self._not_implemented("search_knowledge")
