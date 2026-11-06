"""
Tool registry and gateway.

TRANSPORT INDEPENDENCE
----------------------
Everything here is transport agnostic on purpose. The MCP server (stdio) and the
FastAPI service (HTTP) are both thin adapters over this module. The permission
model, validation, approval gate and audit trail run identically whichever way the
call arrives, which means there is exactly one place where authorisation is decided
rather than two implementations that can drift apart.

That property is worth more than it sounds. The most common way a gateway like this
fails in production is that someone adds an HTTP admin path 'just for operations'
and it quietly bypasses the checks the MCP path enforces.

CALL PIPELINE
-------------
Every invocation, no exceptions:

    1. resolve tool        unknown or denied tool stops here
    2. authorize           role vs tier, server side
    3. validate            types, identifiers, enums, lengths
    4. gate                PRIVILEGED returns an approval request, does not execute
    5. execute             backend call, parameterised
    6. audit               append only, arguments redacted

Failures at any step are still audited. A denial that leaves no trace is worse than
no denial at all.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .audit import ApprovalQueue, AuditLog
from .security import (
    DEFAULT_ROLE,
    NEVER_EXPOSED,
    ROLES,
    ClientRole,
    Decision,
    Tier,
    ValidationError,
    authorize,
    mask_email,
    neutralize_injection,
    validate_enum,
    validate_id,
    validate_limit,
    validate_text,
)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: Tier
    description: str
    input_schema: dict[str, Any]
    handler: Callable[["Gateway", dict[str, Any]], dict[str, Any]]


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------

def _h_find_user(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    q = validate_text("query", a.get("query"))
    users = gw.backend.find_user(q)
    return {"count": len(users), "users": [u.to_dict() for u in users]}


def _h_get_user(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    uid = validate_id("user_id", a.get("user_id"))
    u = gw.backend.get_user(uid)
    if u is None:
        return {"found": False, "user_id": uid}
    return {"found": True, "user": u.to_dict()}


def _h_list_user_groups(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    uid = validate_id("user_id", a.get("user_id"))
    if gw.backend.get_user(uid) is None:
        return {"found": False, "user_id": uid}
    groups = gw.backend.list_user_groups(uid)
    return {
        "found": True,
        "user_id": uid,
        "group_count": len(groups),
        "privileged_count": sum(1 for g in groups if g.privileged),
        "groups": [g.to_dict() for g in groups],
    }


def _h_list_groups(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    groups = gw.backend.list_groups()
    return {"count": len(groups), "groups": [g.to_dict() for g in groups]}


def _h_search_tickets(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    q = validate_text("query", a.get("query"), required=False) or None
    status = a.get("status")
    if status is not None:
        status = validate_enum("status", status)
    limit = validate_limit(a.get("limit"))
    tickets = gw.backend.search_tickets(q, status, limit)
    return {"count": len(tickets), "tickets": [t.to_dict() for t in tickets]}


def _h_get_ticket(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    tid = validate_id("ticket_id", a.get("ticket_id"))
    t = gw.backend.get_ticket(tid)
    if t is None:
        return {"found": False, "ticket_id": tid}
    return {"found": True, "ticket": t.to_dict(),
            "comments": gw.backend.get_ticket_comments(tid)}


def _h_search_knowledge(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    q = validate_text("query", a.get("query"))
    limit = validate_limit(a.get("limit"), default=5, maximum=20)
    return {"results": gw.backend.search_knowledge(q, limit)}


def _h_create_ticket(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    title = validate_text("title", a.get("title"))
    desc = validate_text("description", a.get("description"))
    priority = validate_enum("priority", a.get("priority", "medium"))
    category = validate_text("title", a.get("category", "General"))
    requester = validate_id("user_id", a.get("requester_id"))
    if gw.backend.get_user(requester) is None:
        return {"ok": False, "error": f"unknown requester_id: {requester}"}

    title, t_flag = neutralize_injection(title)
    desc, d_flag = neutralize_injection(desc)

    t = gw.backend.create_ticket(title, desc, priority, category, requester)
    out = {"ok": True, "ticket": t.to_dict()}
    if t_flag or d_flag:
        # Surfaced deliberately. Silently sanitising input hides an attack signal
        # that an operator should see.
        out["injection_markers_neutralized"] = True
    return out


def _h_add_comment(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    tid = validate_id("ticket_id", a.get("ticket_id"))
    body = validate_text("body", a.get("body"))
    body, flag = neutralize_injection(body)
    author = validate_text("title", a.get("author", "agent"))
    res = gw.backend.add_comment(tid, author, body)
    if flag:
        res["injection_markers_neutralized"] = True
    return res


def _h_update_status(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    tid = validate_id("ticket_id", a.get("ticket_id"))
    status = validate_enum("status", a.get("status"))
    # Closing a ticket is a records decision, not a state change an agent should make
    # unilaterally. Raised rather than returned: a business-rule rejection has to
    # surface as a failure at the gateway boundary, otherwise the caller receives
    # ok=True wrapping an inner error and treats it as success.
    if status == "closed":
        raise ValidationError(
            "agents may set status to 'resolved' but not 'closed'; closure is a human action"
        )
    if gw.backend.get_ticket(tid) is None:
        return {"ok": False, "error": f"unknown ticket_id: {tid}"}
    t = gw.backend.update_ticket_status(tid, status)
    return {"ok": True, "ticket": t.to_dict()}


def _h_grant_group(gw: "Gateway", a: dict[str, Any]) -> dict[str, Any]:
    """PRIVILEGED. Only ever reached after a human approval."""
    uid = validate_id("user_id", a.get("user_id"))
    gid = validate_id("group_id", a.get("group_id"))
    return gw.backend.add_user_to_group(uid, gid)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

TOOLS: dict[str, ToolSpec] = {}


def _register(spec: ToolSpec) -> None:
    TOOLS[spec.name] = spec


_register(ToolSpec(
    "find_user", Tier.READ,
    "Search the directory for users by name, email or user ID.",
    {"type": "object",
     "properties": {"query": {"type": "string", "description": "Name, email or partial user ID"}},
     "required": ["query"]},
    _h_find_user,
))

_register(ToolSpec(
    "get_user", Tier.READ,
    "Retrieve a single user record including account status and MFA enrolment.",
    {"type": "object",
     "properties": {"user_id": {"type": "string", "description": "Directory ID, e.g. U1042"}},
     "required": ["user_id"]},
    _h_get_user,
))

_register(ToolSpec(
    "list_user_groups", Tier.READ,
    "List the security groups a user belongs to, flagging privileged membership.",
    {"type": "object",
     "properties": {"user_id": {"type": "string"}},
     "required": ["user_id"]},
    _h_list_user_groups,
))

_register(ToolSpec(
    "list_groups", Tier.READ,
    "List all security groups and whether each is privileged.",
    {"type": "object", "properties": {}},
    _h_list_groups,
))

_register(ToolSpec(
    "search_tickets", Tier.READ,
    "Search service desk tickets by free text and status.",
    {"type": "object",
     "properties": {
         "query": {"type": "string"},
         "status": {"type": "string",
                    "enum": ["new", "in_progress", "pending", "resolved", "closed"]},
         "limit": {"type": "integer", "minimum": 1, "maximum": 50}}},
    _h_search_tickets,
))

_register(ToolSpec(
    "get_ticket", Tier.READ,
    "Retrieve one ticket with its full comment history.",
    {"type": "object",
     "properties": {"ticket_id": {"type": "string", "description": "e.g. INC100042"}},
     "required": ["ticket_id"]},
    _h_get_ticket,
))

_register(ToolSpec(
    "search_knowledge", Tier.READ,
    "Search the IT knowledge base for procedures and policy.",
    {"type": "object",
     "properties": {"query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20}},
     "required": ["query"]},
    _h_search_knowledge,
))

_register(ToolSpec(
    "create_ticket", Tier.WRITE,
    "Open a new service desk ticket on behalf of a user.",
    {"type": "object",
     "properties": {
         "title": {"type": "string"},
         "description": {"type": "string"},
         "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
         "category": {"type": "string"},
         "requester_id": {"type": "string"}},
     "required": ["title", "description", "requester_id"]},
    _h_create_ticket,
))

_register(ToolSpec(
    "add_ticket_comment", Tier.WRITE,
    "Add a work note to an existing ticket.",
    {"type": "object",
     "properties": {"ticket_id": {"type": "string"},
                    "body": {"type": "string"},
                    "author": {"type": "string"}},
     "required": ["ticket_id", "body"]},
    _h_add_comment,
))

_register(ToolSpec(
    "update_ticket_status", Tier.WRITE,
    "Move a ticket to a new status. Agents may resolve but not close.",
    {"type": "object",
     "properties": {"ticket_id": {"type": "string"},
                    "status": {"type": "string",
                               "enum": ["new", "in_progress", "pending", "resolved"]}},
     "required": ["ticket_id", "status"]},
    _h_update_status,
))

_register(ToolSpec(
    "grant_group_membership", Tier.PRIVILEGED,
    ("Add a user to a security group. This changes entitlements, so it is NOT executed "
     "on call: it creates an approval request for a human to action."),
    {"type": "object",
     "properties": {"user_id": {"type": "string"},
                    "group_id": {"type": "string"},
                    "justification": {"type": "string",
                                      "description": "Business reason, shown to the approver"}},
     "required": ["user_id", "group_id", "justification"]},
    _h_grant_group,
))


def _validate_itops_ids(arguments: dict[str, Any]) -> None:
    """Identifier checks for the IT operations tools, run before any handler."""
    for key, kind in (("user_id", "user_id"), ("group_id", "group_id"),
                      ("ticket_id", "ticket_id")):
        if key in arguments and arguments[key] is not None:
            validate_id(kind, arguments[key])


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

class PolicyError(ValueError):
    """A policy that would weaken the permission model is refused at construction."""


@dataclass(frozen=True)
class Policy:
    """Everything a deployment decides: which tools exist, at what tier, which roles
    may reach them, and which actions are never exposed.

    The Gateway enforces a Policy; it does not define one. IT_POLICY below is the
    IT operations set this repository ships with. Another project builds its own
    Policy with its own tools and roles and gets the same pipeline: authorize,
    validate, approval gate, execute, audit.

    Construction refuses three mistakes that would quietly weaken the model:
    a tool that is also on the never-exposed list, a tool registered at DENIED tier
    (denied means not registered), and a default role that does not exist.
    """
    name: str
    tools: Mapping[str, ToolSpec]
    roles: Mapping[str, ClientRole]
    never_exposed: Mapping[str, str] = field(default_factory=dict)
    default_role: str = DEFAULT_ROLE
    validate_arguments: Callable[[dict[str, Any]], None] | None = None

    def __post_init__(self) -> None:
        overlap = set(self.tools) & set(self.never_exposed)
        if overlap:
            raise PolicyError(f"tools also listed as never exposed: {sorted(overlap)}")
        denied = [n for n, t in self.tools.items() if t.tier is Tier.DENIED]
        if denied:
            raise PolicyError(f"tools registered at DENIED tier: {denied}. "
                              "Denied actions belong in never_exposed, not the registry.")
        mismatched = [n for n, t in self.tools.items() if t.name != n]
        if mismatched:
            raise PolicyError(f"registry keys do not match tool names: {mismatched}")
        if self.default_role not in self.roles:
            raise PolicyError(f"default_role '{self.default_role}' is not a defined role")
        # Freeze the mappings so a policy cannot be widened after the gateway is built.
        object.__setattr__(self, "tools", MappingProxyType(dict(self.tools)))
        object.__setattr__(self, "roles", MappingProxyType(dict(self.roles)))
        object.__setattr__(self, "never_exposed", MappingProxyType(dict(self.never_exposed)))

    @classmethod
    def build(cls, name: str, tools: list[ToolSpec], roles: list[ClientRole],
              never_exposed: Mapping[str, str] | None = None,
              default_role: str | None = None,
              validate_arguments: Callable[[dict[str, Any]], None] | None = None) -> "Policy":
        """Convenience constructor from lists."""
        names = [t.name for t in tools]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise PolicyError(f"duplicate tool names: {dupes}")
        return cls(name=name,
                   tools={t.name: t for t in tools},
                   roles={r.name: r for r in roles},
                   never_exposed=dict(never_exposed or {}),
                   default_role=default_role or roles[0].name,
                   validate_arguments=validate_arguments)


IT_POLICY = Policy(
    name="itops",
    tools=TOOLS,
    roles=ROLES,
    never_exposed=NEVER_EXPOSED,
    default_role=DEFAULT_ROLE,
    validate_arguments=_validate_itops_ids,
)


# --------------------------------------------------------------------------
# Gateway
# --------------------------------------------------------------------------

class Gateway:
    """Enforces a Policy. Defaults to the IT operations policy.

    backend is whatever the policy's handlers expect to find at gw.backend; the
    gateway itself never touches it.
    """

    def __init__(self, backend: Any, db_path: str = "data/itops.db",
                 policy: Policy = IT_POLICY):
        self.backend = backend
        self.policy = policy
        self.audit = AuditLog(db_path)
        self.approvals = ApprovalQueue(db_path)

    def list_tools(self, role_name: str) -> list[dict[str, Any]]:
        """Only tools the role can actually reach are advertised.

        A read-only agent is never told that grant_group_membership exists. Hiding
        capability is not the security control - authorize() is - but there is no
        reason to describe a door the caller cannot open.
        """
        out = []
        for spec in self.policy.tools.values():
            auth = self._authorize(role_name, spec.name, spec.tier)
            if auth.decision is Decision.DENY:
                continue
            out.append({
                "name": spec.name,
                "description": spec.description,
                "inputSchema": spec.input_schema,
                "tier": spec.tier.value,
                "requires_approval": spec.tier is Tier.PRIVILEGED,
            })
        return out

    def call_tool(self, tool_name: str, arguments: dict[str, Any],
                  client_id: str = "unknown", role_name: str = "readonly_agent") -> dict[str, Any]:
        started = time.perf_counter()
        arguments = arguments or {}

        # 0. explicitly never-exposed actions
        # Checked before tool resolution so the audit trail records a deliberate
        # denial with its reason, rather than an indistinguishable "unknown tool".
        # If an agent is asking for offboard_user, that is a signal worth seeing.
        never_exposed = self.policy.never_exposed
        if tool_name in never_exposed:
            reason = f"'{tool_name}' is never exposed to agents: {never_exposed[tool_name]}"
            self.audit.record(client_id, role_name, tool_name, Tier.DENIED, Decision.DENY,
                              arguments, reason=reason,
                              duration_ms=(time.perf_counter() - started) * 1000)
            return {"ok": False, "error": "denied", "reason": reason}

        spec = self.policy.tools.get(tool_name)

        # 1. resolve
        if spec is None:
            self.audit.record(client_id, role_name, tool_name, Tier.DENIED, Decision.DENY,
                              arguments, reason="unknown tool")
            return {"ok": False, "error": f"unknown tool: {tool_name}"}

        # 2. authorize
        auth = self._authorize(role_name, tool_name, spec.tier)
        if auth.decision is Decision.DENY:
            self.audit.record(client_id, role_name, tool_name, spec.tier, Decision.DENY,
                              arguments, reason=auth.reason,
                              duration_ms=(time.perf_counter() - started) * 1000)
            return {"ok": False, "error": "denied", "reason": auth.reason}

        # 3. validate
        try:
            if self.policy.validate_arguments is not None:
                self.policy.validate_arguments(arguments)
        except ValidationError as exc:
            self.audit.record(client_id, role_name, tool_name, spec.tier, Decision.DENY,
                              arguments, reason=f"validation: {exc}",
                              duration_ms=(time.perf_counter() - started) * 1000)
            return {"ok": False, "error": "validation_failed", "reason": str(exc)}

        # 4. approval gate
        if auth.decision is Decision.APPROVAL_REQUIRED:
            justification = str(arguments.get("justification", "")).strip()
            if len(justification) < 10:
                self.audit.record(client_id, role_name, tool_name, spec.tier, Decision.DENY,
                                  arguments, reason="justification too short")
                return {"ok": False, "error": "validation_failed",
                        "reason": "a business justification of at least 10 characters is "
                                  "required for privileged actions"}
            req = self.approvals.create(tool_name, arguments, client_id, justification)
            self.audit.record(client_id, role_name, tool_name, spec.tier,
                              Decision.APPROVAL_REQUIRED, arguments,
                              reason=auth.reason,
                              result_summary=f"approval {req['approval_id']} queued",
                              duration_ms=(time.perf_counter() - started) * 1000)
            return {"ok": True, "executed": False, **req}

        # 5. execute
        try:
            result = spec.handler(self, arguments)
        except ValidationError as exc:
            self.audit.record(client_id, role_name, tool_name, spec.tier, Decision.DENY,
                              arguments, reason=f"validation: {exc}",
                              duration_ms=(time.perf_counter() - started) * 1000)
            return {"ok": False, "error": "validation_failed", "reason": str(exc)}
        except Exception as exc:  # noqa: BLE001 - surface as a controlled error, still audited
            self.audit.record(client_id, role_name, tool_name, spec.tier, Decision.ALLOW,
                              arguments, reason=f"error: {type(exc).__name__}",
                              duration_ms=(time.perf_counter() - started) * 1000)
            return {"ok": False, "error": "execution_failed",
                    "reason": "internal error; error type recorded in the audit log"}

        # 6. audit
        elapsed = (time.perf_counter() - started) * 1000
        self.audit.record(client_id, role_name, tool_name, spec.tier, Decision.ALLOW,
                          arguments, reason="permitted",
                          result_summary=_summarize(result), duration_ms=elapsed)
        return {"ok": True, "executed": True, "result": result,
                "duration_ms": round(elapsed, 2)}

    # ---- approval handling: intentionally NOT a tool ----

    def approve(self, approval_id: str, approver: str, approved: bool = True) -> dict[str, Any]:
        """Human decision path. No MCP tool routes here, by design."""
        decision = self.approvals.decide(approval_id, approved, approver)
        if not decision.get("ok"):
            return decision
        if not approved:
            self.audit.record(approver, "human", "approval.deny", Tier.PRIVILEGED,
                              Decision.DENY, {"approval_id": approval_id},
                              reason="denied by approver")
            return decision

        rec = self.approvals.get(approval_id)
        assert rec is not None
        args = self.approvals.arguments_for(approval_id)
        if args is None:
            return {"ok": False, "error": "pending arguments unavailable; re-request the action"}

        spec = self.policy.tools.get(rec["tool_name"])
        if spec is None:
            return {"ok": False, "error": f"unknown tool: {rec['tool_name']}"}

        result = spec.handler(self, args)
        self.approvals.mark_executed(approval_id)
        self.audit.record(approver, "human", rec["tool_name"], spec.tier, Decision.ALLOW,
                          args, reason=f"executed after approval by {approver}",
                          result_summary=_summarize(result))
        return {"ok": True, "approval_id": approval_id, "executed": True,
                "approved_by": approver, "result": result}

    def _authorize(self, role_name: str, tool_name: str, tier: Tier):
        return authorize(role_name, tool_name, tier,
                         roles=self.policy.roles, never_exposed=self.policy.never_exposed)

    def close(self) -> None:
        self.audit.close()
        self.approvals.close()


def _summarize(result: dict[str, Any]) -> str:
    """Short, non-sensitive description for the audit row."""
    if not isinstance(result, dict):
        return str(type(result).__name__)
    for key in ("count", "group_count"):
        if key in result:
            return f"{key}={result[key]}"
    if "ticket" in result and isinstance(result["ticket"], dict):
        return f"ticket={result['ticket'].get('ticket_id')}"
    if "user" in result and isinstance(result["user"], dict):
        return f"user={result['user'].get('user_id')}"
    if "found" in result:
        return f"found={result['found']}"
    if "ok" in result:
        return f"ok={result['ok']}"
    return "ok"
