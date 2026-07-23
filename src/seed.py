"""
Seed the demo database.

Synthetic data, generated here so the repository is self-contained and contains no
real user records. Seeded, so the demo is identical every run.

The data is shaped to make the security model demonstrable rather than to look
impressive: there are privileged groups, disabled accounts, users without MFA, and
tickets that request access. Those are the cases where an agent's permissions
actually matter.
"""
from __future__ import annotations

import argparse
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 42

SCHEMA = """
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS kb_articles;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS approvals;

CREATE TABLE users (
    user_id       TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    email         TEXT NOT NULL,
    department    TEXT NOT NULL,
    manager_id    TEXT,
    status        TEXT NOT NULL,
    mfa_enrolled  INTEGER NOT NULL
);

CREATE TABLE groups (
    group_id     TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL,
    privileged   INTEGER NOT NULL
);

CREATE TABLE memberships (
    user_id   TEXT NOT NULL REFERENCES users(user_id),
    group_id  TEXT NOT NULL REFERENCES groups(group_id),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE tickets (
    ticket_id     TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    status        TEXT NOT NULL,
    priority      TEXT NOT NULL,
    category      TEXT NOT NULL,
    requester_id  TEXT NOT NULL REFERENCES users(user_id),
    assignee_id   TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE comments (
    comment_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id   TEXT NOT NULL REFERENCES tickets(ticket_id),
    author      TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE kb_articles (
    article_id  TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    summary     TEXT NOT NULL,
    body        TEXT NOT NULL,
    category    TEXT NOT NULL
);

-- Append-only. No UPDATE or DELETE path exists anywhere in the codebase.
CREATE TABLE audit_log (
    entry_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    client_role  TEXT NOT NULL,
    tool_name    TEXT NOT NULL,
    tier         TEXT NOT NULL,
    decision     TEXT NOT NULL,
    reason       TEXT,
    arguments    TEXT NOT NULL,
    result_summary TEXT,
    duration_ms  REAL
);

CREATE TABLE approvals (
    approval_id    TEXT PRIMARY KEY,
    tool_name      TEXT NOT NULL,
    arguments      TEXT NOT NULL,
    requested_by   TEXT NOT NULL,
    requested_at   TEXT NOT NULL,
    justification  TEXT NOT NULL,
    status         TEXT NOT NULL,
    decided_by     TEXT,
    decided_at     TEXT
);

CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_audit_ts ON audit_log(timestamp);
CREATE INDEX idx_audit_tool ON audit_log(tool_name);
"""

FIRST = ["Dana", "Marcus", "Priya", "Elena", "Tom", "Aisha", "Ben", "Carla", "David",
         "Grace", "Hector", "Ingrid", "Jamal", "Karen", "Luis", "Mei", "Noah",
         "Olivia", "Pavel", "Quinn", "Rosa", "Sam", "Tara", "Uma", "Victor", "Wendy"]
LAST = ["Ellis", "Okonkwo", "Raman", "Vasquez", "Bergstrom", "Khan", "Cole", "Duarte",
        "Feld", "Hayes", "Ibarra", "Jonsson", "Kim", "Lowe", "Marek", "Nguyen",
        "Ortiz", "Park", "Quist", "Reyes", "Silva", "Tan", "Ubl", "Vance"]
DEPTS = ["Clinical Operations", "Network Engineering", "Practice Support",
         "Data Platform", "Finance", "Revenue Cycle", "Security", "IT Operations"]

GROUPS = [
    ("GRP-0001", "All Staff", "Baseline access for every employee", 0),
    ("GRP-0002", "VPN Users", "Remote network access", 0),
    ("GRP-0003", "Reporting Readers", "Read-only analytics dashboards", 0),
    ("GRP-0004", "Practice Support", "Practice-facing support tooling", 0),
    ("GRP-0005", "Clinical App Users", "Access to clinical applications", 0),
    ("GRP-0006", "Data Platform Contributors", "Write access to data platform", 0),
    ("GRP-0007", "Helpdesk Agents", "ITSM agent console", 0),
    ("GRP-0008", "Security Analysts", "SIEM and detection tooling", 1),
    ("GRP-0009", "Infrastructure Admins", "Server and hypervisor administration", 1),
    ("GRP-0010", "Identity Admins", "Directory and group administration", 1),
    ("GRP-0011", "PHI Data Access", "Access to protected health information", 1),
    ("GRP-0012", "Global Administrators", "Tenant-wide administrative control", 1),
]

KB = [
    ("KB-1001", "Resetting a forgotten password",
     "Self-service password reset steps and fallback to the service desk.",
     "Users can reset via the self-service portal. If MFA is not enrolled the reset must be "
     "performed by the service desk after identity verification.", "Identity"),
    ("KB-1002", "Requesting access to a security group",
     "How access requests are raised, reviewed and approved.",
     "Access requests are raised as tickets. Requests for privileged groups require manager "
     "approval and a documented business justification. Standing access is avoided in favour "
     "of just-in-time elevation.", "Identity"),
    ("KB-1003", "VPN connection failures",
     "Common causes of VPN failures and triage order.",
     "Check certificate expiry first, then group membership in VPN Users, then client version. "
     "Most failures are certificate related.", "Network"),
    ("KB-1004", "MFA enrolment for new starters",
     "Enrolment procedure and grace period policy.",
     "New starters must enrol within five business days. Accounts without MFA after the grace "
     "period are restricted from remote access.", "Identity"),
    ("KB-1005", "Handling PHI access requests",
     "Additional controls that apply to protected health information.",
     "PHI access requires role justification, manager approval and privacy office review. "
     "Access is time-bound and recertified quarterly. It is never granted by automation.",
     "Compliance"),
    ("KB-1006", "Escalating a P1 incident",
     "Escalation path and communication expectations for critical incidents.",
     "Page the on-call engineer, open a bridge, and notify the IT Director within fifteen "
     "minutes. Update the ticket every thirty minutes until resolved.", "Incident Management"),
    ("KB-1007", "Onboarding checklist for new employees",
     "Account, group and equipment provisioning steps.",
     "Create the account, assign baseline groups, enrol MFA, issue equipment, and confirm "
     "manager sign-off before enabling remote access.", "Onboarding"),
    ("KB-1008", "Offboarding and access revocation",
     "Steps taken when an employee leaves.",
     "Access revocation is performed by the identity team through the offboarding workflow. "
     "It is deliberately excluded from automation and from agent tooling.", "Offboarding"),
]

TICKET_TEMPLATES = [
    ("Cannot connect to VPN", "Connection drops immediately after authenticating.", "Network", "high"),
    ("Request access to Reporting Readers", "Need dashboard access for quarterly reporting.", "Access Request", "low"),
    ("Password reset required", "Locked out after too many attempts, MFA not enrolled.", "Identity", "medium"),
    ("New starter account setup", "Account and baseline groups needed for Monday start.", "Onboarding", "medium"),
    ("Laptop running slowly after update", "Performance degraded following the latest patch cycle.", "Endpoint", "low"),
    ("Request access to Data Platform Contributors", "Need write access to build ingestion jobs.", "Access Request", "medium"),
    ("Shared mailbox permissions", "Cannot send as the practice support shared mailbox.", "Collaboration", "low"),
    ("Printer offline in clinic", "Front desk printer not reachable from the network.", "Endpoint", "medium"),
    ("MFA device replacement", "Phone replaced, need to re-enrol authenticator.", "Identity", "medium"),
    ("Certificate expiry warning", "Client certificate expires in seven days.", "Network", "high"),
    ("Request access to PHI Data Access", "Need patient record access for care coordination work.", "Access Request", "high"),
    ("Application timeout during peak hours", "Clinical app times out between 9 and 11am.", "Application", "critical"),
    ("Onboarding: equipment not delivered", "Laptop has not arrived for a start date tomorrow.", "Onboarding", "high"),
    ("Slack channel access", "Need access to the incident response channel.", "Collaboration", "low"),
    ("SSO login loop", "Redirect loop when signing in to the analytics portal.", "Identity", "high"),
]


def seed(db_path: str | Path = "data/itops.db") -> dict[str, int]:
    rng = random.Random(SEED)
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)

    # ---- users ----
    users = []
    n_users = 60
    for i in range(n_users):
        uid = f"U{1000 + i}"
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        email = name.lower().replace(" ", ".") + "@example-health.org"
        dept = rng.choice(DEPTS)
        status = "active" if rng.random() > 0.08 else rng.choice(["disabled", "suspended"])
        mfa = 1 if rng.random() > 0.15 else 0
        users.append((uid, name, email, dept, None, status, mfa))

    # managers, assigned after the population exists
    users = [
        (u[0], u[1], u[2], u[3],
         (f"U{1000 + rng.randrange(0, 8)}" if i >= 8 else None),
         u[5], u[6])
        for i, u in enumerate(users)
    ]
    conn.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?)", users)

    # ---- groups ----
    conn.executemany("INSERT INTO groups VALUES (?,?,?,?)", GROUPS)

    # ---- memberships ----
    memberships = set()
    for uid, *_ in users:
        memberships.add((uid, "GRP-0001"))
        for gid, _n, _d, priv in GROUPS[1:]:
            p = 0.06 if priv else 0.30
            if rng.random() < p:
                memberships.add((uid, gid))
    conn.executemany("INSERT INTO memberships VALUES (?,?)", sorted(memberships))

    # ---- tickets ----
    now = datetime.now(timezone.utc)
    statuses = ["new", "in_progress", "pending", "resolved", "closed"]
    tickets, comments = [], []
    for i in range(120):
        title, desc, cat, pri = rng.choice(TICKET_TEMPLATES)
        created = now - timedelta(days=rng.randrange(0, 90), hours=rng.randrange(0, 24))
        updated = created + timedelta(hours=rng.randrange(1, 72))
        tid = f"INC{100001 + i}"
        requester = rng.choice(users)[0]
        assignee = rng.choice(users)[0] if rng.random() > 0.3 else None
        tickets.append((tid, title, desc, rng.choice(statuses), pri, cat, requester,
                        assignee, created.isoformat(timespec="seconds"),
                        updated.isoformat(timespec="seconds")))
        for _ in range(rng.randrange(0, 3)):
            comments.append((tid, rng.choice(users)[1],
                             rng.choice([
                                 "Acknowledged, investigating.",
                                 "Asked the requester for more detail.",
                                 "Escalated to the network team.",
                                 "Applied the documented workaround.",
                                 "Awaiting manager approval before proceeding.",
                                 "Confirmed resolved with the requester.",
                             ]),
                             (created + timedelta(hours=rng.randrange(1, 48))).isoformat(timespec="seconds")))
    conn.executemany("INSERT INTO tickets VALUES (?,?,?,?,?,?,?,?,?,?)", tickets)
    conn.executemany(
        "INSERT INTO comments (ticket_id, author, body, created_at) VALUES (?,?,?,?)", comments
    )

    # ---- knowledge base ----
    conn.executemany("INSERT INTO kb_articles VALUES (?,?,?,?,?)", KB)

    conn.commit()
    counts = {
        "users": len(users),
        "groups": len(GROUPS),
        "memberships": len(memberships),
        "tickets": len(tickets),
        "comments": len(comments),
        "kb_articles": len(KB),
    }
    conn.close()
    return counts


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Seed the demo IT operations database.")
    ap.add_argument("--db", default="data/itops.db")
    args = ap.parse_args()
    c = seed(args.db)
    print(f"seeded {args.db}")
    for k, v in c.items():
        print(f"  {k:<14} {v:>5}")
    priv = sum(1 for g in GROUPS if g[3])
    print(f"\n  privileged groups: {priv} of {len(GROUPS)}")
    print("  (privileged group membership is the action that requires human approval)")
