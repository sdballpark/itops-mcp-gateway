# IT Operations MCP Gateway

A Model Context Protocol server that lets AI agents work with IT service management
and identity systems, with the permission model that makes it safe to do so.

The interesting part is not that an agent can look up a user or open a ticket. It is
what happens when it asks to add someone to the Global Administrators group.

---

## The problem

Give an agent an API token and it can do everything the token can do. That is fine
until the agent is wrong, or until someone gets a hostile instruction into a ticket
body that an agent later reads.

The failure modes are not hypothetical:

- An agent adds a user to a privileged group because a ticket asked it to.
- An agent offboards an active employee mid shift because it misread a request.
- A ticket body containing "ignore previous instructions" is summarised by an agent
  the following week.
- Something goes wrong and nobody can reconstruct which agent did what.

This gateway is the layer that sits between the agent and the systems of record and
answers one question on every call: **what is the identity behind this agent actually
entitled to do?**

---

## Four permission tiers

Every tool is assigned exactly one tier at registration. The tier, not the tool,
determines what happens.

| Tier | Behaviour | Examples |
|---|---|---|
| **READ** | Executes immediately | `find_user`, `search_tickets`, `search_knowledge` |
| **WRITE** | Executes, fully audited | `create_ticket`, `add_ticket_comment` |
| **PRIVILEGED** | **Does not execute.** Returns an approval request for a human | `grant_group_membership` |
| **DENIED** | Never registered as a tool at all | `offboard_user`, `elevate_to_admin`, `reset_mfa` |

The distinction between PRIVILEGED and DENIED is the one worth defending.

Privileged actions are legitimate but need a human, so they are exposed behind a gate.
Denied actions are ones no agent should ever perform, so they are not exposed at all
and the agent has no way to name them. Offboarding is the clearest case: it is a
routine business process, and it is exactly the process you never want an agent to
trigger, because the failure mode is locking a clinician out of patient records
mid shift.

### Why not just tell the model not to

Because a prompt is not a security boundary. An instruction telling a model not to
call a tool is a suggestion. Not registering the tool is a control. Everything here
is enforced server side, after the model has already decided what it wants.

---

## Client roles

An agent connects as a role supplied by the operator, never one it names itself.

| Role | Ceiling | Purpose |
|---|---|---|
| `readonly_agent` | READ | Answers questions. Changes nothing. Sees 7 tools. |
| `servicedesk_agent` | WRITE | Works tickets. Cannot touch entitlements. Sees 10 tools. |
| `access_request_agent` | PRIVILEGED | Handles access requests; privileged actions queue for approval. Sees 11 tools. |

An unrecognised role fails closed to `readonly_agent`. Failing closed is the only
sensible default for a permission system.

---

## Run the demo

```bash
pip install -r requirements.txt
python src/seed.py      # synthetic directory, tickets, knowledge base
python demo.py          # walks all six scenarios
python -m pytest tests/ -q
```

`demo.py` exits non-zero if any security invariant breaks, and runs in CI on every
commit, so the scenarios are verified rather than being a script that rotted.

### Browse it

```bash
uvicorn src.api:app --reload
```

Then open **http://localhost:8000/docs**. Useful endpoints:

| Endpoint | What it shows |
|---|---|
| `GET /roles` | The permission model as data, including every never-exposed action and why |
| `GET /tools` | Tools visible to a role. Change `X-Client-Role` and watch the list change |
| `POST /call` | Invoke any tool |
| `GET /approvals` | The human approval queue |
| `POST /approvals/{id}/decide` | Approve or deny. This is the surface no agent can reach |
| `GET /audit/summary` | Call volumes, decisions, and recent denials |

### As an MCP server

```json
{
  "mcpServers": {
    "itops-gateway": {
      "command": "python",
      "args": ["src/mcp_server.py"],
      "env": { "MCP_CLIENT_ROLE": "servicedesk_agent", "ITOPS_DB": "data/itops.db" }
    }
  }
}
```

---

## Architecture

```
   AI agent
      │
      │ MCP (stdio)                    HTTP
      ▼                                  ▼
 ┌──────────────┐                ┌──────────────┐
 │ mcp_server.py│                │    api.py    │   ← approvals live here,
 └──────┬───────┘                └───────┬──────┘     outside the tool surface
        │                                │
        └──────────────┬─────────────────┘
                       ▼
              ┌─────────────────┐
              │   gateway.py    │   resolve → authorize → validate
              │                 │   → gate → execute → audit
              └────────┬────────┘
                       │
        ┌──────────────┼───────────────┐
        ▼              ▼               ▼
  security.py      audit.py       backends.py
  tiers, roles,    append-only    SQLite (demo)
  validation,      log, approval  ServiceNow (stub)
  redaction        queue          Entra ID (stub)
```

Both transports share `gateway.py`. That is the single most important property here:
there is one place authorisation is decided, not two implementations that drift.
The most common way a gateway like this fails in production is somebody adding an
HTTP admin path "just for operations" that quietly bypasses the agent path's checks.

---

## What else is enforced

**Stored prompt injection.** A ticket body is read back by agents later, which makes
it an injection vector: file a ticket containing "ignore all previous instructions"
and wait. Markers are neutralised (wrapped, not deleted) so the text stays readable
for a human, and the event is surfaced in the response rather than silently swallowed.

**Injection through tool arguments.** Every query is parameterised. That is the real
control; identifier pattern validation is defence in depth, not the primary defence.
There is a test that fires `'; DROP TABLE users; --` through a search and asserts the
table survives.

**Audit redaction.** Everything written to the log passes through a redactor:
sensitive keys by name, bearer tokens, long opaque strings, SSN-shaped values. The
log has to prove what happened without becoming a second place secrets accumulate.

**Append-only audit.** No UPDATE or DELETE path exists anywhere in the codebase, and
`modify_audit_log` is in the never-exposed list, so the gateway cannot rewrite its
own record.

**Agents cannot approve themselves.** There is no `approve` tool. No sequence of
model outputs reaches that path. A second identity check in the approval queue is
belt and braces.

---

## Tests

28 tests, weighted toward security invariants rather than functionality. The four
that matter most:

```
test_readonly_agent_cannot_write
test_privileged_action_does_not_execute_on_call
test_never_exposed_tools_are_unreachable
test_agent_cannot_approve_its_own_request
```

CI runs the full suite, then re-runs the invariants as a separate gating job, then
runs the demo end to end. The Docker build runs the suite too, so an image is never
produced from a state where the permission model is broken.

---

## On the data

The backend is **SQLite with synthetic data**, generated by `src/seed.py`. No real
user records, no credentials, and it starts anywhere with nothing configured.

That is a deliberate architectural choice rather than a shortcut. The agent never
talks to ServiceNow or Entra ID directly, so everything interesting lives above the
backend interface. Pointing this at a real instance means implementing the same
interface; nothing in the security layer changes. The `ServiceNowBackend` and
`EntraIDBackend` stubs in `src/backends.py` document exactly which API calls each
would make and how their credentials would be scoped.

The Entra stub is worth reading: the Graph permissions listed are the narrowest that
work (`User.Read.All`, `GroupMember.ReadWrite.All`) and deliberately **not**
`Directory.ReadWrite.All`, which would also permit deletion and role assignment. The
permission gradient is enforced twice, once here and once at the API scope, so a bug
in the gateway still cannot grant capability the token does not carry.

---

## Documentation

- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — the threat model and every control, in detail
- [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md) — decisions, tradeoffs, and what changed during the build
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) — operating procedures, approvals, incident response

---

## What this does not claim

Synthetic data, single node, no production traffic. It demonstrates a security
architecture for agent-to-enterprise integration; it is not evidence of having run
one at scale. `docs/DESIGN_NOTES.md` covers what would change under real load.

MIT licensed.
