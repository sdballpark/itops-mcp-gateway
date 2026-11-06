"""
Policy tests.

The gateway enforces whatever Policy it is given. These tests build a small policy
that has nothing to do with IT operations and check that it gets the same pipeline:
its own tools only, its own roles, its own never-exposed list, the approval gate and
the audit trail. They also check that a policy which would weaken the model is
refused when it is built, rather than discovered when it is exploited.
"""
from __future__ import annotations

import pytest

from itops_mcp_gateway import (
    IT_POLICY,
    ClientRole,
    Gateway,
    Policy,
    PolicyError,
    Tier,
    ToolSpec,
    ValidationError,
)

SCHEMA = {"type": "object", "properties": {"record_id": {"type": "string"}}}


class Store:
    """Stand-in backend. The gateway never touches it; only handlers do."""

    def __init__(self):
        self.records = {"R1": "first record"}
        self.sent: list[str] = []


def _lookup(gw, a):
    return {"record": gw.backend.records.get(a.get("record_id"))}


def _note(gw, a):
    return {"noted": True}


def _send(gw, a):
    gw.backend.sent.append(a["record_id"])
    return {"sent": a["record_id"]}


def _validate(a):
    rid = a.get("record_id")
    if rid is not None and not str(rid).startswith("R"):
        raise ValidationError("record_id must start with R")


def _policy() -> Policy:
    return Policy.build(
        name="test",
        tools=[
            ToolSpec("lookup_record", Tier.READ, "Read a record", SCHEMA, _lookup),
            ToolSpec("add_note", Tier.WRITE, "Add a note", SCHEMA, _note),
            ToolSpec("send_record", Tier.PRIVILEGED, "Send a record outside", SCHEMA, _send),
        ],
        roles=[
            ClientRole("reader", "Reads only", Tier.READ),
            ClientRole("investigator", "Reads, writes, requests sends", Tier.PRIVILEGED),
        ],
        never_exposed={"delete_record": "Irreversible."},
        validate_arguments=_validate,
    )


@pytest.fixture()
def gw(tmp_path):
    g = Gateway(Store(), str(tmp_path / "policy.db"), policy=_policy())
    yield g
    g.close()


def test_default_gateway_still_uses_it_policy(tmp_path):
    g = Gateway(Store(), str(tmp_path / "d.db"))
    assert g.policy is IT_POLICY
    g.close()


def test_custom_policy_exposes_only_its_own_tools(gw):
    names = {t["name"] for t in gw.list_tools("investigator")}
    assert names == {"lookup_record", "add_note", "send_record"}
    assert not names & set(IT_POLICY.tools)


def test_it_tools_are_unknown_under_a_custom_policy(gw):
    r = gw.call_tool("find_user", {"query": "x"}, "t", "investigator")
    assert r["ok"] is False and "unknown tool" in r["error"]


def test_custom_roles_are_enforced(gw):
    r = gw.call_tool("add_note", {"record_id": "R1"}, "t", "reader")
    assert r["error"] == "denied"
    assert gw.call_tool("lookup_record", {"record_id": "R1"}, "t", "reader")["ok"] is True


def test_it_roles_do_not_exist_under_a_custom_policy(gw):
    r = gw.call_tool("lookup_record", {"record_id": "R1"}, "t", "access_request_agent")
    assert r["error"] == "denied"


def test_custom_never_exposed_is_denied_and_audited(gw):
    r = gw.call_tool("delete_record", {"record_id": "R1"}, "t", "investigator")
    assert r["error"] == "denied" and "never exposed" in r["reason"]
    assert gw.audit.tail(1)[0]["tool_name"] == "delete_record"


def test_custom_validation_runs_before_the_handler(gw):
    r = gw.call_tool("lookup_record", {"record_id": "X9"}, "t", "investigator")
    assert r["error"] == "validation_failed"


def test_privileged_tool_waits_for_human_approval(gw):
    r = gw.call_tool("send_record", {"record_id": "R1",
                                     "justification": "regulator asked for it"},
                     "agent-1", "investigator")
    assert r["executed"] is False
    assert gw.backend.sent == []

    self_approval = gw.approve(r["approval_id"], approver="investigator_agent")
    assert self_approval["ok"] is False
    assert gw.backend.sent == []

    d = gw.approve(r["approval_id"], approver="dana.reviewer")
    assert d["executed"] is True and gw.backend.sent == ["R1"]


def test_policy_cannot_be_widened_after_construction():
    p = _policy()
    with pytest.raises(TypeError):
        p.tools["new_tool"] = None  # type: ignore[index]


def test_policy_refuses_tool_that_is_also_never_exposed():
    with pytest.raises(PolicyError, match="never exposed"):
        Policy.build("bad", [ToolSpec("delete_record", Tier.WRITE, "d", SCHEMA, _note)],
                     [ClientRole("r", "r", Tier.WRITE)],
                     never_exposed={"delete_record": "no"})


def test_policy_refuses_denied_tier_registration():
    with pytest.raises(PolicyError, match="DENIED"):
        Policy.build("bad", [ToolSpec("x", Tier.DENIED, "x", SCHEMA, _note)],
                     [ClientRole("r", "r", Tier.READ)])


def test_policy_refuses_unknown_default_role():
    with pytest.raises(PolicyError, match="default_role"):
        Policy.build("bad", [ToolSpec("x", Tier.READ, "x", SCHEMA, _note)],
                     [ClientRole("r", "r", Tier.READ)], default_role="nobody")


def test_policy_refuses_duplicate_tool_names():
    with pytest.raises(PolicyError, match="duplicate"):
        Policy.build("bad", [ToolSpec("x", Tier.READ, "x", SCHEMA, _note),
                             ToolSpec("x", Tier.WRITE, "x", SCHEMA, _note)],
                     [ClientRole("r", "r", Tier.WRITE)])
