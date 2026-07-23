# Security Model

The question this gateway answers on every call: **what is the identity behind this
agent actually entitled to do?**

Not what the model asked for. Not what the prompt said it should be allowed to do.
What the identity is entitled to do, decided server side, after the model has already
made up its mind.

---

## 1. Threat model

What we are defending against, in rough order of likelihood.

### T1 — The agent is simply wrong
Most likely by a wide margin. A model misreads a request and calls the wrong tool
with plausible-looking arguments. No malice required.

**Control:** tier system. The blast radius of a wrong call is bounded by what the
role can reach. A `readonly_agent` being wrong produces a bad answer; it cannot
produce a bad change.

### T2 — Stored prompt injection
A user files a ticket containing instructions and waits for an agent to read it. This
is the realistic attack in an ITSM context, because the attacker does not need access
to the agent at all — only the ability to open a ticket.

**Control:** injection markers in free text are neutralised on write, and the event is
surfaced rather than swallowed. More fundamentally, T1's control applies: even a
fully hijacked agent is bounded by its role.

### T3 — Confused deputy
The agent has more authority than the user it is acting for. A user asks for
something they could not do themselves, and the agent does it because the agent can.

**Control:** privileged actions do not execute. A human sees the request, the
justification, and the target before anything changes.

### T4 — Injection through tool arguments
An LLM passes a quote character, a SQL fragment, or a path traversal into a tool
argument.

**Control:** parameterised queries everywhere. Identifier validation is defence in
depth, not the primary defence. There is a test that fires a DROP TABLE through a
search parameter and asserts the table survives.

### T5 — Privilege escalation via the gateway itself
The gateway holds credentials to identity and ITSM systems. It is a target.

**Control:** the production backend credential is itself narrowly scoped, so the
gateway cannot exercise capability its token does not carry even if application logic
is bypassed. Never-exposed actions are absent from the tool registry entirely.

### T6 — Untraceable action
Something changed and nobody can reconstruct who or what did it.

**Control:** append-only audit of every call, including denials, with redaction.

### Explicitly out of scope
Transport security (TLS terminates upstream), authentication of the agent itself
(handled by the MCP client's own auth), and the security of the model provider. This
gateway assumes it is talking to an authenticated client and decides what that client
may do.

---

## 2. The tier system

| Tier | Executes? | Human? | Registered as a tool? |
|---|---|---|---|
| READ | Yes | No | Yes |
| WRITE | Yes | No | Yes |
| PRIVILEGED | **No** | **Yes** | Yes, with a warning in the description |
| DENIED | Never | n/a | **No** |

### Tier assignment rules

An action is **PRIVILEGED** if it changes what someone is entitled to do. Group
membership, license assignment, role grants.

An action is **DENIED** if it satisfies any of:

- Irreversible within a normal working timeframe
- Blast radius extends to people other than the requester
- The failure mode has consequences outside IT
- It is a known attack primitive

`offboard_user` hits all four. That is why it is not a tool.

### The current never-exposed list

| Action | Reason |
|---|---|
| `offboard_user` | Irreversible, time critical. Locking out an active clinician is a patient safety issue, not just an IT one. |
| `delete_user` | Destroys audit history. Unrecoverable. |
| `revoke_all_access` | Same blast radius as offboarding. No legitimate agent use. |
| `elevate_to_admin` | The single action an attacker most wants. Routes through PIM with human approval, never an agent. |
| `reset_mfa` | An account takeover primitive. Requires verified identity, which an agent cannot establish. |
| `modify_audit_log` | The log is append only. Nothing alters it, including this gateway. |

These are documented rather than merely absent, so a reviewer can see the omission
was a decision. `GET /roles` serves the list at runtime.

---

## 3. Defence in depth

Three independent layers. Each assumes the one above it may fail.

**Layer 1 — Registration.** A denied tool is never advertised. The agent cannot name
what it does not know exists. This is the weakest layer, because a determined caller
can guess a name; it is here to reduce the surface, not to be relied on.

**Layer 2 — Authorisation.** `authorize()` runs on every invocation regardless of
what was advertised. Role versus tier, decided server side. This is the primary
control.

**Layer 3 — Backend scope.** The production credential is scoped so that even a total
compromise of layers 1 and 2 cannot exercise capability the token does not carry. The
Entra ID stub documents this: `User.Read.All` and `GroupMember.ReadWrite.All`, and
deliberately not `Directory.ReadWrite.All`.

The layers are ordered by strength ascending, which is the right way round. If the
only real control were "we did not tell the model about it," that would be a
disclosure control masquerading as an access control.

---

## 4. The approval gate

A privileged call returns:

```json
{
  "ok": true,
  "executed": false,
  "approval_id": "APR-84ca2a80a19e",
  "status": "pending",
  "message": "This action changes entitlements and was NOT executed. A human must
              approve it. The requesting agent cannot approve its own request."
}
```

Three properties matter:

**`executed: false` is explicit.** The agent is told plainly that nothing happened, so
it reports accurately to the user rather than claiming success.

**A justification of at least ten characters is required.** Not a real quality bar,
but it forces the agent to articulate a reason that a human then reads. In practice
the justification is the most useful thing in the approval queue.

**The agent cannot approve.** There is no `approve` tool, so no sequence of model
outputs reaches that path. Approval happens over HTTP by a human. A second check in
the approval queue rejects approver identities ending in `_agent`, which is belt and
braces rather than the actual control.

---

## 5. Audit

Every call is logged: allowed, denied, approval-required, and errored.

**Denials matter more than successes.** A run of denied privileged calls means either
an agent is misconfigured or something is probing what it can reach. `GET
/audit/summary` surfaces `recent_denials` for exactly this reason.

**Redaction happens before the write**, not on read. Sensitive keys by name
(`password`, `token`, `secret`, `api_key`, `ssn`, and others), bearer tokens by
pattern, long opaque strings, SSN-shaped values. Emails are partially masked in
contexts where correlation matters more than the full address.

**Append only.** No UPDATE or DELETE path exists in the codebase. `modify_audit_log`
is in the never-exposed list.

---

## 6. Mapping to common control frameworks

Not a compliance claim, but the mapping a reviewer will ask about.

| Control area | Where it lives |
|---|---|
| Least privilege | Tier system, role ceilings, backend credential scoping |
| Separation of duties | Approval gate; requester and approver cannot be the same identity |
| Audit logging | `audit.py`, append only, redacted |
| Input validation | `security.py` validators, parameterised queries |
| Change control | Privileged actions require documented justification and human approval |
| Data minimisation | Redaction before write, partial email masking |
| Fail closed | Unknown role defaults to `readonly_agent`; unknown tool denies |

For a healthcare environment specifically: PHI group membership is privileged, so it
cannot be granted by automation. `KB-1005` in the seeded knowledge base states the
policy, and the demo uses PHI access as the worked example precisely because it is
the case where getting this wrong matters most.

---

## 7. Known limitations

**No rate limiting.** A misbehaving agent could generate a large volume of allowed
READ calls. In production this belongs at the gateway ingress.

**Approval queue is in-process.** Pending arguments are held in memory, so a restart
loses them and the action must be re-requested. That fails safe rather than
dangerous, but a production deployment needs durable storage.

**No approver authorisation.** Any identity not ending in `_agent` can approve. Real
deployments must check the approver against a group and, for privileged grants,
against the target user's management chain.

**Single tenant.** No notion of which organisation a request belongs to.

**Redaction is pattern based.** It catches known shapes. A secret in an unusual
format could pass through. Structured secrets management upstream is the real answer.
