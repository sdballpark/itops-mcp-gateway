"""
IT Operations MCP Gateway.

A tool gateway that sits between AI agents and systems of record and decides, on
every call, what the identity behind the agent is entitled to do.

The gateway enforces a Policy. This package ships one, IT_POLICY, for IT service
management and identity tools. Other projects define their own:

    from itops_mcp_gateway import ClientRole, Gateway, Policy, Tier, ToolSpec

    policy = Policy.build(
        name="my-project",
        tools=[ToolSpec("lookup", Tier.READ, "Read a record", schema, handler)],
        roles=[ClientRole("reader", "Reads records", Tier.READ)],
        never_exposed={"delete_everything": "Irreversible."},
    )
    gw = Gateway(backend=my_backend, db_path="data/my.db", policy=policy)

Every call to gw.call_tool runs the same pipeline regardless of policy: never-exposed
check, authorization, argument validation, approval gate, execution, audit.
"""
from __future__ import annotations

__version__ = "1.2.0"

from .gateway import IT_POLICY, Gateway, Policy, PolicyError, ToolSpec
from .security import (
    ClientRole,
    Decision,
    Tier,
    ValidationError,
    neutralize_injection,
    redact,
    validate_text,
)

__all__ = [
    "IT_POLICY",
    "ClientRole",
    "Decision",
    "Gateway",
    "Policy",
    "PolicyError",
    "Tier",
    "ToolSpec",
    "ValidationError",
    "__version__",
    "neutralize_injection",
    "redact",
    "validate_text",
]
