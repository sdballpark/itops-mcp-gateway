# Runbook

Operating procedures for the IT Operations MCP Gateway.

---

## Deploy

```bash
docker build -t itops-mcp-gateway .
docker run -d --name itops-gw -p 8000:8000 itops-mcp-gateway
```

The build seeds the database and runs the test suite. If a security invariant fails,
no image is produced. That is intentional: the permission model is treated as a
build-breaking property.

Verify:

```bash
curl -s localhost:8000/ready        # {"status":"ready", ...}
curl -s localhost:8000/roles | head # permission model as data
```

`/health` is liveness (process up). `/ready` is readiness (can actually serve). They
are separate so an orchestrator pulls a broken container out of rotation rather than
letting it serve errors.

---

## Connect an agent

Set the role in the MCP client configuration, never in the agent's own context:

```json
{
  "mcpServers": {
    "itops-gateway": {
      "command": "python",
      "args": ["-m", "itops_mcp_gateway.mcp_server"],
      "env": { "MCP_CLIENT_ROLE": "servicedesk_agent" }
    }
  }
}
```

Choosing a role:

- **`readonly_agent`**: start here. Covers question answering and triage assistance.
- **`servicedesk_agent`**: when the agent should open and update tickets.
- **`access_request_agent`**: only when someone is available to work the approval
  queue. This role generates human work by design.

An unrecognised role fails closed to `readonly_agent` and logs a warning to stderr.

---

## Work the approval queue

```bash
curl -s localhost:8000/approvals
```

For each pending request, check:

1. **Justification**: does it name a business reason, not just a restatement?
2. **Target user**: is the account active? Is MFA enrolled?
3. **Group**: is it privileged? PHI Data Access and Global Administrators always
   warrant a second look.
4. **Requesting agent**: does this agent normally make requests like this?

Approve:

```bash
curl -s -X POST localhost:8000/approvals/APR-xxxx/decide \
  -H "Authorization: Bearer $APPROVER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"approved":true}'
```

Deny by setting `"approved": false`. Both outcomes are audited with the identity tied
to your approver key. There is no field for typing a name.

**Never give an approver key to an agent or put one in an agent's configuration.**
Agent keys are rejected at this endpoint, and keeping approver keys out of agent
environments is what keeps that true.

---

## Monitor

```bash
curl -s localhost:8000/audit/summary
```

What to watch, in priority order:

**`recent_denials`.** The most useful field. A handful is normal. A run of denied
privileged calls from the same client means either a misconfigured agent or something
probing what it can reach. Investigate the same day.

**`by_decision`.** A rising `approval_required` count with a flat approval rate means
the queue is not being worked, and agents are generating requests nobody actions.

**`injection_markers_neutralized`.** Not in the summary, but grep the audit table.
Any occurrence means someone put instruction-shaped text into a ticket. One is worth
reading. Several from one requester is an incident.

---

## Incident response

### An agent did something unexpected

```bash
curl -s "localhost:8000/audit?limit=100"
```

Every call is recorded with client ID, role, tool, tier, decision, redacted
arguments, and duration. Reconstruct the sequence before changing anything.

### An agent is misbehaving now

Stop the MCP client, or restart the gateway with `MCP_CLIENT_ROLE=readonly_agent`.
Demoting the role is faster than stopping the service and keeps read paths working
while you investigate.

```bash
docker stop itops-gw
docker run -d --name itops-gw-ro -p 8000:8000 \
  -e MCP_CLIENT_ROLE=readonly_agent itops-mcp-gateway
```

### A privileged action was approved in error

The gateway does not reverse actions; that is deliberate, since an automated undo is
another privileged action. Reverse it in the system of record directly, then record
the correction in the originating ticket. The audit trail retains both the approval
and the approver.

### Suspected compromise of the gateway credential

1. Revoke the credential at the identity provider first, not last.
2. Stop the container.
3. Export the audit table for the incident record.
4. Review every `allow` decision on PRIVILEGED tier since the credential was issued.
5. Reissue scoped to the minimum the tool registry requires, and verify the new token
   cannot exercise anything outside it.

---

## Adding a tool

1. Write the handler. For the IT tools that is `src/itops_mcp_gateway/gateway.py`;
   another project writes it in its own code and adds it to its own `Policy`.
2. Register it with an explicit tier. **Decide the tier first**, before the schema.
3. If it changes entitlements it is PRIVILEGED. If it is irreversible, has blast
   radius beyond the requester, or is an attack primitive, it belongs in the
   policy's never-exposed list with a written reason instead. A policy that puts the
   same name in both places is refused when it is built.
4. Add a test asserting what the tool must *not* do.
5. Run `python demo.py` and confirm it still exits zero.

Never add a tool at DENIED tier as a way of documenting it. Denied means not
registered; `NEVER_EXPOSED` is where it goes.

---

## Disaster recovery

Stateless apart from the SQLite database.

```bash
sqlite3 data/itops.db ".backup data/itops-backup.db"
```

In production the systems of record are the source of truth for users and tickets;
only the audit log and approval history are unique to the gateway. **Back those up
independently and treat the audit log as the higher-value artefact**: it is the only
record of what the agents did.

Recovery: redeploy the image, restore the audit database, verify `/ready`, reconnect
clients. Expect pending approvals to be lost; they must be re-requested, which fails
safe.
