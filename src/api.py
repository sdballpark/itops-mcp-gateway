"""
HTTP adapter.

Two reasons this exists alongside the MCP server:

  1. The approval workflow needs a surface the agent cannot reach. There is no
     'approve' MCP tool, deliberately, so no sequence of model outputs can approve
     an action the model itself requested. Approvals happen here, by a human.

  2. It makes the gateway demonstrable without an MCP client attached. Open /docs
     and every tool is callable from a browser.

It shares gateway.py with the MCP server, so the permission model cannot drift
between the two transports. That is the single most important property of this file:
the most common way a gateway like this fails is someone adding an HTTP admin path
'just for operations' that quietly bypasses the checks the agent path enforces.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from contextlib import asynccontextmanager  # noqa: E402

from fastapi import FastAPI, Header, HTTPException  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from backends import SQLiteBackend  # noqa: E402
from gateway import Gateway  # noqa: E402
from security import NEVER_EXPOSED, ROLES  # noqa: E402

DB_PATH = os.environ.get("ITOPS_DB", "data/itops.db")

_state: dict[str, Any] = {"gateway": None, "ready": False, "error": None}


@asynccontextmanager
async def lifespan(_app: "FastAPI"):
    """Open the backend at startup, fail loudly rather than on first request."""
    try:
        if not Path(DB_PATH).exists():
            raise FileNotFoundError(f"{DB_PATH} not found. Run `python src/seed.py` first.")
        _state["gateway"] = Gateway(SQLiteBackend(DB_PATH), DB_PATH)
        _state["ready"] = True
    except Exception as exc:  # noqa: BLE001
        _state["ready"] = False
        _state["error"] = str(exc)
    yield
    if _state["gateway"] is not None:
        _state["gateway"].close()


app = FastAPI(
    lifespan=lifespan,
    title="IT Operations MCP Gateway",
    version="1.0.0",
    description=(
        "Secure tool gateway between AI agents and IT operations systems. "
        "Four permission tiers, human approval for entitlement changes, "
        "append-only audit trail."
    ),
)

def gw() -> Gateway:
    if not _state["ready"]:
        raise HTTPException(status_code=503, detail=_state.get("error", "not ready"))
    return _state["gateway"]


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

class ToolCall(BaseModel):
    tool: str = Field(..., description="Tool name, e.g. find_user")
    arguments: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    approver: str = Field(..., description="Human approver identity, e.g. dwayne.rhule")
    approved: bool = True


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------

@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    """Liveness. The process is up. Says nothing about whether it can serve."""
    return {"status": "ok"}


@app.get("/ready", tags=["ops"])
def ready() -> dict[str, Any]:
    """Readiness. Distinct from liveness on purpose: a container that is alive but
    has no database should fail readiness so it is pulled from the load balancer
    rather than serving errors."""
    if not _state["ready"]:
        raise HTTPException(status_code=503, detail=_state.get("error", "not ready"))
    return {"status": "ready", "database": DB_PATH}


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

@app.get("/roles", tags=["security"])
def roles() -> dict[str, Any]:
    """The permission model, served as data.

    Being able to show this to an auditor without reading source is the point.
    """
    return {
        "roles": [
            {"name": r.name, "description": r.description, "max_tier": r.max_tier.value}
            for r in ROLES.values()
        ],
        "never_exposed": [
            {"tool": name, "reason": reason} for name, reason in NEVER_EXPOSED.items()
        ],
    }


@app.get("/tools", tags=["tools"])
def list_tools(x_client_role: str = Header(default="readonly_agent")) -> dict[str, Any]:
    """Tools visible to the given role. Pass X-Client-Role to compare."""
    role = x_client_role if x_client_role in ROLES else "readonly_agent"
    tools = gw().list_tools(role)
    return {"role": role, "count": len(tools), "tools": tools}


# --------------------------------------------------------------------------
# Invocation
# --------------------------------------------------------------------------

@app.post("/call", tags=["tools"])
def call(
    body: ToolCall,
    x_client_role: str = Header(default="readonly_agent"),
    x_client_id: str = Header(default="http-client"),
) -> dict[str, Any]:
    """Invoke a tool.

    The role arrives as a header rather than in the request body, mirroring how a
    deployment supplies it as configuration rather than letting the caller choose.
    An unrecognised role fails closed to readonly_agent.
    """
    role = x_client_role if x_client_role in ROLES else "readonly_agent"
    return gw().call_tool(body.tool, body.arguments, client_id=x_client_id, role_name=role)


# --------------------------------------------------------------------------
# Approvals: the human surface. No MCP tool reaches these.
# --------------------------------------------------------------------------

@app.get("/approvals", tags=["approvals"])
def pending_approvals() -> dict[str, Any]:
    items = gw().approvals.pending()
    return {"count": len(items), "pending": items}


@app.get("/approvals/{approval_id}", tags=["approvals"])
def get_approval(approval_id: str) -> dict[str, Any]:
    rec = gw().approvals.get(approval_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"unknown approval_id: {approval_id}")
    return rec


@app.post("/approvals/{approval_id}/decide", tags=["approvals"])
def decide(approval_id: str, body: ApprovalDecision) -> dict[str, Any]:
    """Approve or deny a queued privileged action.

    On approval the action executes here, not in the agent's session. The approver
    identity is recorded in the audit trail alongside the original request.
    """
    result = gw().approve(approval_id, body.approver, body.approved)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "decision failed"))
    return result


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

@app.get("/audit", tags=["audit"])
def audit_tail(limit: int = 25) -> dict[str, Any]:
    return {"entries": gw().audit.tail(min(max(limit, 1), 200))}


@app.get("/audit/summary", tags=["audit"])
def audit_summary() -> dict[str, Any]:
    """Aggregates an operator would actually watch.

    recent_denials is the interesting field. A run of denied privileged calls means
    either an agent is misconfigured or something is probing what it can reach.
    """
    return gw().audit.summary()
