"""
HTTP credentials.

The MCP transport gets its role from operator configuration (MCP_CLIENT_ROLE in the
server's environment), which the agent cannot change. The HTTP transport needs the
same property, so identity there comes from a credential the operator issued, never
from a header or field the caller fills in.

Two separate namespaces:

  agents     key -> (client_id, role)   used on POST /call
  approvers  key -> approver identity   used on POST /approvals/{id}/decide

An agent key presented to the approval endpoint does not match anything, because it
is not in the approver namespace. That is the control. The agent never holds a
credential that can approve, so no output it produces can approve.

Only SHA-256 hashes of keys are stored. Comparison uses hmac.compare_digest.

Generate a credentials file for the demo:

    python -m itops_mcp_gateway.credentials

The plaintext keys are printed once and not written to disk.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

CREDENTIALS_PATH = os.environ.get("ITOPS_CREDENTIALS", "data/credentials.json")


@dataclass(frozen=True)
class AgentIdentity:
    client_id: str
    role: str


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


class CredentialStore:
    def __init__(self, agents: dict[str, dict[str, str]], approvers: dict[str, str]):
        self._agents = agents
        self._approvers = approvers

    @classmethod
    def load(cls, path: str | Path = CREDENTIALS_PATH) -> "CredentialStore":
        """Missing file means no credentials at all. Callers fail closed on that."""
        p = Path(path)
        if not p.exists():
            return cls({}, {})
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(data.get("agents", {}), data.get("approvers", {}))

    @property
    def has_approvers(self) -> bool:
        return bool(self._approvers)

    @staticmethod
    def _match(token: str | None, table: dict) -> str | None:
        if token is None:
            return None
        digest = _hash(token)
        found = None
        for stored in table:
            if hmac.compare_digest(stored, digest):
                found = stored
        return found

    def agent(self, authorization: str | None) -> AgentIdentity | None:
        hit = self._match(_bearer(authorization), self._agents)
        if hit is None:
            return None
        rec = self._agents[hit]
        return AgentIdentity(client_id=rec["client_id"], role=rec["role"])

    def approver(self, authorization: str | None) -> str | None:
        hit = self._match(_bearer(authorization), self._approvers)
        return None if hit is None else self._approvers[hit]


def generate(path: str | Path = CREDENTIALS_PATH) -> dict[str, str]:
    """Write a demo credentials file and return the plaintext keys."""
    plain = {
        "readonly_agent": secrets.token_urlsafe(32),
        "servicedesk_agent": secrets.token_urlsafe(32),
        "access_request_agent": secrets.token_urlsafe(32),
        "approver:dwayne.rhule": secrets.token_urlsafe(32),
    }
    data = {
        "agents": {
            _hash(plain[role]): {"client_id": f"demo-{role}", "role": role}
            for role in ("readonly_agent", "servicedesk_agent", "access_request_agent")
        },
        "approvers": {_hash(plain["approver:dwayne.rhule"]): "dwayne.rhule"},
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return plain


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else CREDENTIALS_PATH
    keys = generate(out)
    print(f"Wrote hashed credentials to {out}. Plaintext keys, shown once:\n")
    for name, key in keys.items():
        print(f"  {name:28s} {key}")
    print("\nSend as:  Authorization: Bearer <key>")


if __name__ == "__main__":
    main()
