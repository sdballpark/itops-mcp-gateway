"""
MCP server (stdio transport).

Uses the official Model Context Protocol SDK. This file is deliberately thin: it
translates between MCP's JSON-RPC surface and the Gateway, and does nothing else.
All authorisation, validation, approval gating and auditing happen in gateway.py, so
the HTTP adapter in api.py enforces exactly the same rules through exactly the same
code path.

CLIENT ROLE
-----------
The agent's role is supplied by the operator through MCP_CLIENT_ROLE, not by the
agent itself. That matters: if the model could name its own role it would be able to
escalate simply by asking. The role is part of the deployment configuration, in the
same way a service principal is.

Valid roles: readonly_agent, servicedesk_agent, access_request_agent.
Defaults to readonly_agent if unset or invalid, because failing closed is the only
sensible default for a permission system.

RUNNING IT
----------
Configure in an MCP client (Claude Desktop, for example) as:

    {
      "mcpServers": {
        "itops-gateway": {
          "command": "python",
          "args": ["src/mcp_server.py"],
          "env": {
            "MCP_CLIENT_ROLE": "servicedesk_agent",
            "ITOPS_DB": "data/itops.db"
          }
        }
      }
    }
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mcp.types as types  # noqa: E402
from mcp.server import Server  # noqa: E402
from mcp.server.stdio import stdio_server  # noqa: E402

from backends import SQLiteBackend  # noqa: E402
from gateway import Gateway  # noqa: E402
from security import ROLES  # noqa: E402

DB_PATH = os.environ.get("ITOPS_DB", "data/itops.db")
CLIENT_ID = os.environ.get("MCP_CLIENT_ID", "mcp-client")

_requested_role = os.environ.get("MCP_CLIENT_ROLE", "readonly_agent")
CLIENT_ROLE = _requested_role if _requested_role in ROLES else "readonly_agent"

server = Server("itops-gateway")
_gateway: Gateway | None = None


def gateway() -> Gateway:
    global _gateway
    if _gateway is None:
        _gateway = Gateway(SQLiteBackend(DB_PATH), DB_PATH)
    return _gateway


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """Advertise only what this role can reach.

    A read-only agent never learns that grant_group_membership exists. That is not
    the security boundary - authorize() is, and it runs again on every call - but
    there is no reason to describe a door the caller cannot open.
    """
    return [
        types.Tool(
            name=t["name"],
            description=(
                f"{t['description']}"
                + ("\n\nNOTE: this action requires human approval and will NOT execute "
                   "immediately. It returns an approval request." if t["requires_approval"] else "")
            ),
            inputSchema=t["inputSchema"],
        )
        for t in gateway().list_tools(CLIENT_ROLE)
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    """Every call goes through the same pipeline as the HTTP path."""
    result = gateway().call_tool(
        tool_name=name,
        arguments=arguments or {},
        client_id=CLIENT_ID,
        role_name=CLIENT_ROLE,
    )
    return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


async def main() -> None:
    print(
        f"itops-gateway starting | role={CLIENT_ROLE} | db={DB_PATH}",
        file=sys.stderr,
    )
    if _requested_role != CLIENT_ROLE:
        print(
            f"WARNING: requested role '{_requested_role}' is not recognised; "
            f"failing closed to '{CLIENT_ROLE}'",
            file=sys.stderr,
        )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
