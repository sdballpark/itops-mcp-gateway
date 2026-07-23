# Design Notes

Decisions, tradeoffs, and the things that changed during the build.

---

## 1. Why the tier is on the tool, not on the caller

The obvious design is a permission matrix: role x tool, a grid of booleans. It is
also the design that rots. Every new tool needs a decision for every role, the grid
grows quadratically, and the interesting question ("is this dangerous?") gets buried
in bookkeeping.

Assigning a tier at registration inverts it. The tool author answers one question:
what class of action is this? Roles then declare a ceiling. Adding a tool requires no
change to any role, and adding a role requires no change to any tool.

The cost is expressiveness. You cannot say "this role gets exactly these three write
tools and no others" without the `denied_tools` escape hatch, which exists but is
empty. If it starts filling up, the tier model is being fought rather than used, and
that is the signal to revisit.

## 2. PRIVILEGED and DENIED are different things

The first version had three tiers, with dangerous actions simply not implemented.
That is not the same as a documented decision, and a reviewer cannot tell the
difference between "we thought about offboarding and excluded it" and "nobody got
round to offboarding."

`NEVER_EXPOSED` makes the omission explicit and serves it at `GET /roles`. The list
is now the most useful artefact for an auditor, because it states what the system
will not do and why, rather than requiring someone to infer it from absence.

## 3. Transport independence, enforced by structure

The MCP server and the HTTP API are both thin adapters over `gateway.py`. That was
deliberate from the start, for one reason: the most common way a gateway like this
fails in production is that someone adds an HTTP admin path "just for operations" and
it bypasses the checks the agent path enforces.

Sharing the pipeline means there is one place authorisation is decided. The approval
endpoints are the only thing that exists on one transport and not the other, and that
asymmetry is the point rather than an accident.

## 4. The bug the tests caught

`update_ticket_status` originally returned `{"ok": False, "error": ...}` when an agent
tried to close a ticket. The test asserted the call failed, and it did not: the
gateway wrapped the handler's result as `{"ok": True, "executed": True, "result":
{"ok": False, ...}}`.

The outer envelope said success. A caller checking `ok` would have believed the ticket
closed.

The fix was to raise `ValidationError` from the handler instead of returning an error
dict, so a business-rule rejection surfaces as a failure at the gateway boundary. The
general lesson is worth stating: **a rejection buried inside a success envelope is
worse than no check at all**, because it produces confident wrong behaviour rather
than visible failure.

That test was written to assert a policy and instead caught a structural inconsistency
in error handling. Which is the argument for writing tests against properties rather
than against implementations.

## 5. Neutralising injection instead of rejecting it

The first instinct with a ticket body containing "ignore all previous instructions"
is to reject the write. That is wrong for two reasons.

A user legitimately quoting the phrase, for instance reporting the attack, gets their
ticket refused. And rejecting throws away the signal: the most useful thing about a
hostile ticket is knowing it was filed.

So markers are wrapped rather than removed. The text stays readable for a human, the
instruction is broken for a model, and `injection_markers_neutralized: true` comes
back in the response so an operator sees it happened.

## 6. Synthetic data as an architectural choice

The demo runs on SQLite with generated data. That is not only expedience.

The premise of an MCP gateway is that the agent never touches the system of record
directly. Everything that matters lives above the backend interface. Making the
backend swappable and demonstrating on SQLite proves the boundary is real: if the
security model depended on ServiceNow specifics, it would not run on SQLite at all.

The stubs carry the production detail. `EntraIDBackend` documents the exact Graph
permissions, and specifically why it uses `GroupMember.ReadWrite.All` rather than
`Directory.ReadWrite.All`. That is the part worth reviewing, and it is more useful
written down than it would be buried in a working integration.

## 7. Approval arguments held in memory

When a privileged call is gated, the redacted arguments go to the approvals table and
the unredacted arguments stay in process memory keyed by approval ID.

The reason is that writing unredacted arguments to a table would create exactly the
accumulation of sensitive data the redaction exists to prevent. The cost is that a
restart loses pending approvals and the action must be re-requested.

That tradeoff is correct at this scale and wrong at production scale, where you need
durable pending state. The right answer there is an encrypted column with a
short TTL, not a plaintext one. Noted as a limitation rather than solved, because
solving it properly needs a key management story this project does not have.

## 8. What would change at production scale

**Rate limiting at ingress.** Nothing here bounds call volume. A looping agent
generates unlimited READ traffic.

**Durable approval state**, per above.

**Real approver authorisation.** Any non-agent identity can currently approve.
Production needs group membership checks and, for privileged grants, verification
against the target's management chain.

**Structured logging to a SIEM.** The audit table is queryable but local. Real
deployments ship to Splunk or Sentinel, and the denial stream is what you alert on.

**Per-tenant isolation.** Single tenant today, with no notion of which organisation a
request belongs to.

**Token-level scoping verification at startup.** The gateway should assert at boot
that its credential does not carry permissions beyond what its tool registry needs,
and refuse to start if it does. That turns layer 3 from a deployment convention into
an enforced invariant.

## 9. What this project does not demonstrate

- Production traffic, or any traffic
- Real ServiceNow or Entra ID integration
- Multi-node deployment or failover
- Performance under load
- An actual MCP client driving it end to end in anger

It demonstrates a security architecture and the reasoning behind it. That is the
claim, and overstating it would undercut the parts that are real.
