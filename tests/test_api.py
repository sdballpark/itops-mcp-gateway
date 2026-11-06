"""
HTTP transport tests.

The gateway tests prove the permission model. These prove the HTTP adapter cannot be
used to walk around it: a caller cannot pick its own role, and cannot approve a
privileged action without an approver credential the agent never holds.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from credentials import generate  # noqa: E402
from seed import seed  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "api.db"
    seed(db)
    creds = tmp_path / "credentials.json"
    keys = generate(creds)
    monkeypatch.setenv("ITOPS_DB", str(db))
    monkeypatch.setenv("ITOPS_CREDENTIALS", str(creds))
    import api
    importlib.reload(api)
    with TestClient(api.app) as c:
        yield c, keys


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _queue_privileged(c, keys) -> str:
    r = c.post("/call", headers=_auth(keys["access_request_agent"]), json={
        "tool": "grant_group_membership",
        "arguments": {"user_id": "U1003", "group_id": "GRP-0009",
                      "justification": "access request approved by manager in INC100042"},
    }).json()
    assert r.get("approval_id", "").startswith("APR-"), r
    return r["approval_id"]


def test_role_header_is_ignored(client):
    """A caller naming itself access_request_agent in a header gets nothing for it."""
    c, _ = client
    r = c.post("/call", headers={"X-Client-Role": "access_request_agent"}, json={
        "tool": "grant_group_membership",
        "arguments": {"user_id": "U1003", "group_id": "GRP-0009",
                      "justification": "access request approved by manager in INC100042"},
    }).json()
    assert "approval_id" not in r
    assert r["error"] == "denied", r


def test_missing_credential_fails_closed_to_readonly(client):
    c, _ = client
    r = c.post("/call", json={"tool": "create_ticket", "arguments": {
        "title": "Printer offline", "description": "front desk printer",
        "requester_id": "U1000", "priority": "medium"}}).json()
    assert r["error"] == "denied", r


def test_approval_requires_approver_credential(client):
    c, keys = client
    approval_id = _queue_privileged(c, keys)
    r = c.post(f"/approvals/{approval_id}/decide", json={"approved": True})
    assert r.status_code == 401


def test_agent_credential_cannot_approve(client):
    """The HTTP version of test_agent_cannot_approve_its_own_request."""
    c, keys = client
    approval_id = _queue_privileged(c, keys)
    for role in ("readonly_agent", "servicedesk_agent", "access_request_agent"):
        r = c.post(f"/approvals/{approval_id}/decide",
                   headers=_auth(keys[role]), json={"approved": True})
        assert r.status_code == 401, role
    assert c.get(f"/approvals/{approval_id}").json()["status"] == "pending"


def test_approver_name_cannot_be_supplied_by_caller(client):
    c, keys = client
    approval_id = _queue_privileged(c, keys)
    r = c.post(f"/approvals/{approval_id}/decide",
               json={"approved": True, "approver": "dwayne.rhule"})
    assert r.status_code == 401


def test_approver_credential_executes_and_is_recorded(client):
    c, keys = client
    approval_id = _queue_privileged(c, keys)
    r = c.post(f"/approvals/{approval_id}/decide",
               headers=_auth(keys["approver:dwayne.rhule"]), json={"approved": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["executed"] is True
    assert body["approved_by"] == "dwayne.rhule"


def test_no_approvers_configured_fails_closed(tmp_path, monkeypatch):
    db = tmp_path / "api.db"
    seed(db)
    monkeypatch.setenv("ITOPS_DB", str(db))
    monkeypatch.setenv("ITOPS_CREDENTIALS", str(tmp_path / "missing.json"))
    import api
    importlib.reload(api)
    with TestClient(api.app) as c:
        r = c.post("/approvals/APR-000000000000/decide", json={"approved": True})
        assert r.status_code == 503
