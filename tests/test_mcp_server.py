"""
MCP transport tests.

The MCP server is the path a real agent uses, so it is tested through the MCP SDK's
own request handlers rather than by calling gateway functions directly. This would
have caught the SDK 2.x break, where the server stopped importing at all.
"""
from __future__ import annotations

import asyncio
import importlib
import json

import mcp.types as types
import pytest

from itops_mcp_gateway.seed import seed


def _load(tmp_path, monkeypatch, role: str):
    db = tmp_path / "mcp.db"
    seed(db)
    monkeypatch.setenv("ITOPS_DB", str(db))
    monkeypatch.setenv("MCP_CLIENT_ROLE", role)
    import itops_mcp_gateway.mcp_server as m
    m = importlib.reload(m)
    return m


def _list(m) -> list[str]:
    handler = m.server.request_handlers[types.ListToolsRequest]
    result = asyncio.run(handler(types.ListToolsRequest(method="tools/list")))
    return [t.name for t in result.root.tools]


def _call(m, name: str, arguments: dict) -> dict:
    handler = m.server.request_handlers[types.CallToolRequest]
    req = types.CallToolRequest(method="tools/call",
                                params=types.CallToolRequestParams(name=name,
                                                                   arguments=arguments))
    result = asyncio.run(handler(req))
    return json.loads(result.root.content[0].text)


def test_mcp_server_starts_and_lists_tools(tmp_path, monkeypatch):
    m = _load(tmp_path, monkeypatch, "readonly_agent")
    names = _list(m)
    assert "find_user" in names
    assert "grant_group_membership" not in names


def test_mcp_unknown_role_fails_closed(tmp_path, monkeypatch):
    m = _load(tmp_path, monkeypatch, "superuser_agent")
    assert m.CLIENT_ROLE == "readonly_agent"


def test_mcp_privileged_call_queues_for_approval(tmp_path, monkeypatch):
    m = _load(tmp_path, monkeypatch, "access_request_agent")
    r = _call(m, "grant_group_membership",
              {"user_id": "U1003", "group_id": "GRP-0009",
               "justification": "access request approved by manager in INC100042"})
    assert r["executed"] is False and r["approval_id"].startswith("APR-")


@pytest.mark.parametrize("tool", ["offboard_user", "reset_mfa"])
def test_mcp_never_exposed_tools_are_denied(tmp_path, monkeypatch, tool):
    m = _load(tmp_path, monkeypatch, "access_request_agent")
    r = _call(m, tool, {"user_id": "U1003"})
    assert r["error"] == "denied"
