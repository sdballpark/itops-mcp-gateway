"""
The security model.

This is the part that matters. Exposing IT systems to an AI agent is not hard;
exposing them safely is. The controls here answer one question: what is the identity
behind the agent actually entitled to do?

FOUR TIERS
----------
Every tool is assigned exactly one tier at registration. The tier, not the tool,
determines what happens when it is called.

  READ        Retrieval only. No state change. Executes immediately.
  WRITE       Changes state in a way that is reversible and low blast radius,
              for example opening a ticket. Executes immediately, fully audited.
  PRIVILEGED  Changes entitlements. Does NOT execute. Returns an approval request
              that a human must action. The agent cannot approve its own request.
  DENIED      Never registered as a tool at all. The agent has no way to name it.

The distinction between PRIVILEGED and DENIED is the one worth defending. Privileged
actions are legitimate but need a human in the loop, so they are exposed behind a
gate. Denied actions are ones no agent should perform under any circumstances, so
they are not exposed at all. Offboarding is the clearest example: it is a normal
business process, and it is exactly the process you never want an agent to trigger
because the failure mode is locking out a clinician mid shift.

WHY NOT JUST FILTER AT THE PROMPT
---------------------------------
Because prompts are not a security boundary. An instruction telling a model not to
call a tool is a suggestion; not registering the tool is a control. Everything here
is enforced server side, after the model has already decided what it wants.

DEFENCE IN DEPTH
----------------
Three independent layers, in order:
  1. Registration    a denied tool is never advertised
  2. Authorisation   the client role is checked against the tool's tier
  3. Backend scope   the production backend credential is itself narrowly scoped,
                     so a bug in layers 1 and 2 still cannot grant capability the
                     token does not carry (see backends.EntraIDBackend docstring)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Tier(str, Enum):
    READ = "read"
    WRITE = "write"
    PRIVILEGED = "privileged"
    DENIED = "denied"


class Decision(str, Enum):
    ALLOW = "allow"
    APPROVAL_REQUIRED = "approval_required"
    DENY = "deny"


# --------------------------------------------------------------------------
# Client roles
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ClientRole:
    """An agent connects as a role, not as a person.

    Roles are deliberately coarse. A finer grained model is possible, but every
    additional role is another thing to get wrong, and three tiers of agent covers
    the realistic cases: something that only reads, something that works tickets,
    and something that can request entitlement changes for a human to approve.
    """
    name: str
    description: str
    max_tier: Tier
    denied_tools: frozenset[str] = frozenset()

    def permits(self, tier: Tier) -> bool:
        order = {Tier.READ: 0, Tier.WRITE: 1, Tier.PRIVILEGED: 2, Tier.DENIED: 99}
        return order[tier] <= order[self.max_tier]


ROLES: dict[str, ClientRole] = {
    "readonly_agent": ClientRole(
        name="readonly_agent",
        description="Answers questions from ITSM and directory data. Cannot change anything.",
        max_tier=Tier.READ,
    ),
    "servicedesk_agent": ClientRole(
        name="servicedesk_agent",
        description="Works tickets. Can open and update them, cannot change entitlements.",
        max_tier=Tier.WRITE,
    ),
    "access_request_agent": ClientRole(
        name="access_request_agent",
        description=("Handles access requests end to end. Privileged actions are queued "
                     "for human approval rather than executed."),
        max_tier=Tier.PRIVILEGED,
    ),
}

DEFAULT_ROLE = "readonly_agent"


# --------------------------------------------------------------------------
# Tools that are never exposed
# --------------------------------------------------------------------------

# Documented rather than merely absent, because a reviewer should be able to see
# that the omission was a decision. Each of these is a real IT operations action
# that some other system performs; none of them belongs behind an agent.
NEVER_EXPOSED: dict[str, str] = {
    "offboard_user": "Irreversible and time critical. Locking out an active clinician "
                     "is a patient safety issue, not just an IT one.",
    "delete_user": "Destroys audit history and is unrecoverable.",
    "revoke_all_access": "Same blast radius as offboarding, no legitimate agent use.",
    "elevate_to_admin": "Privilege escalation is the single action an attacker most "
                        "wants. It routes through PIM with human approval, never an agent.",
    "reset_mfa": "Resetting MFA on an account is an account takeover primitive. "
                 "Requires verified identity, which an agent cannot establish.",
    "modify_audit_log": "The audit log is append only. Nothing may alter it, including "
                        "this gateway.",
}


# --------------------------------------------------------------------------
# Authorisation
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthResult:
    decision: Decision
    reason: str


def authorize(role_name: str, tool_name: str, tier: Tier) -> AuthResult:
    """Server side authorisation. Called on every tool invocation."""
    if tool_name in NEVER_EXPOSED:
        return AuthResult(Decision.DENY,
                          f"'{tool_name}' is never exposed to agents: {NEVER_EXPOSED[tool_name]}")

    role = ROLES.get(role_name)
    if role is None:
        return AuthResult(Decision.DENY, f"unknown client role '{role_name}'")

    if tool_name in role.denied_tools:
        return AuthResult(Decision.DENY, f"'{tool_name}' is denied for role '{role_name}'")

    if tier is Tier.DENIED:
        return AuthResult(Decision.DENY, f"'{tool_name}' is tier DENIED")

    if not role.permits(tier):
        return AuthResult(
            Decision.DENY,
            f"role '{role_name}' permits up to {role.max_tier.value}, "
            f"'{tool_name}' requires {tier.value}",
        )

    if tier is Tier.PRIVILEGED:
        return AuthResult(Decision.APPROVAL_REQUIRED,
                          f"'{tool_name}' changes entitlements and requires human approval")

    return AuthResult(Decision.ALLOW, "permitted")


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------

class ValidationError(ValueError):
    pass


# Identifiers are machine generated and have a known shape. Anything that does not
# match is rejected before it reaches the backend. This is not the primary defence
# against injection (parameterised queries are), but it keeps malformed input from
# travelling further into the system than it needs to.
ID_PATTERNS = {
    "user_id": re.compile(r"^U\d{4,6}$"),
    "group_id": re.compile(r"^GRP-\d{4}$"),
    "ticket_id": re.compile(r"^INC\d{6}$"),
    "approval_id": re.compile(r"^APR-[0-9a-f]{12}$"),
}

ENUMS = {
    "priority": {"low", "medium", "high", "critical"},
    "status": {"new", "in_progress", "pending", "resolved", "closed"},
}

MAX_LEN = {"title": 200, "description": 4000, "body": 4000,
           "query": 200, "justification": 1000}

# Free text written into a ticket may later be read back by another agent. Markers
# that look like instruction injection are neutralised rather than rejected, so a
# user legitimately quoting one of these phrases still gets their ticket filed.
INJECTION_MARKERS = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions"
    r"|disregard\s+(the\s+)?above"
    r"|system\s*:\s*you\s+are"
    r"|</?(system|assistant|tool_call)>)",
    re.IGNORECASE,
)


def validate_id(kind: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{kind} must be a string")
    pattern = ID_PATTERNS.get(kind)
    if pattern and not pattern.match(value):
        raise ValidationError(f"{kind} '{value}' is not a valid identifier")
    return value


def validate_enum(kind: str, value: Any) -> str:
    allowed = ENUMS.get(kind, set())
    if value not in allowed:
        raise ValidationError(f"{kind} must be one of {sorted(allowed)}, got '{value}'")
    return str(value)


def validate_text(field: str, value: Any, required: bool = True) -> str:
    if value is None:
        if required:
            raise ValidationError(f"{field} is required")
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    v = value.strip()
    if required and not v:
        raise ValidationError(f"{field} must not be empty")
    limit = MAX_LEN.get(field, 1000)
    if len(v) > limit:
        raise ValidationError(f"{field} exceeds {limit} characters")
    return v


def neutralize_injection(text: str) -> tuple[str, bool]:
    """Defang instruction-injection markers in free text.

    Ticket bodies are read back by agents later, which makes them a stored injection
    vector: a user files a ticket containing 'ignore previous instructions' and waits
    for an agent to summarise it. Wrapping the marker in brackets preserves the text
    for a human reader while breaking it as an instruction.
    """
    if not INJECTION_MARKERS.search(text):
        return text, False
    return INJECTION_MARKERS.sub(lambda m: f"[neutralized: {m.group(0)}]", text), True


def validate_limit(value: Any, default: int = 10, maximum: int = 50) -> int:
    if value is None:
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError("limit must be an integer")
    if n < 1:
        raise ValidationError("limit must be at least 1")
    return min(n, maximum)


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------

# Applied to everything written to the audit log. The log is the record you hand to
# an auditor, which means it must prove what happened without itself becoming a
# place secrets accumulate.
SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "client_secret",
    "authorization", "auth", "credential", "credentials", "ssn", "social_security",
    "dob", "date_of_birth", "private_key", "session_id", "cookie",
}

REDACTED = "[REDACTED]"

BEARER = re.compile(r"\b(bearer\s+)[A-Za-z0-9._\-]{12,}", re.IGNORECASE)
SSNISH = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def _redact_string(s: str) -> str:
    s = BEARER.sub(r"\1" + REDACTED, s)
    s = SSNISH.sub(REDACTED, s)
    s = LONG_TOKEN.sub(REDACTED, s)
    return s


def redact(obj: Any) -> Any:
    """Recursively redact sensitive values. Keys are matched case-insensitively."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj


def mask_email(email: str) -> str:
    """Partial masking for logs: enough to correlate, not enough to harvest."""
    if "@" not in email:
        return REDACTED
    local, _, domain = email.partition("@")
    keep = local[:2] if len(local) > 2 else local[:1]
    return f"{keep}{'*' * max(len(local) - len(keep), 1)}@{domain}"
