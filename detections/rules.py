from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime, timezone
import uuid


@dataclass
class Alert:
    id: str
    rule_id: str
    name: str
    severity: str
    mitre_id: str
    mitre_technique: str
    description: str
    confidence: float
    matched_event_count: int
    affected_accounts: List[str]
    affected_ips: List[str]
    first_seen: str
    last_seen: str
    triage_steps: List[str]
    matched_events: List[Dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "confidence": self.confidence,
            "matched_event_count": self.matched_event_count,
            "affected_accounts": self.affected_accounts,
            "affected_ips": self.affected_ips,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "triage_steps": self.triage_steps,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _accounts(events: List[Dict]) -> List[str]:
    accts = set()
    for e in events:
        for f in ["SubjectUserName", "TargetUserName", "actor_username"]:
            v = e.get(f)
            if v and v not in ("-", "ANONYMOUS LOGON", ""):
                accts.add(v)
    return list(accts)


def _ips(events: List[Dict]) -> List[str]:
    ips = set()
    for e in events:
        for f in ["IpAddress", "ClientAddress", "RequestingMachine"]:
            v = e.get(f, "")
            if v:
                # Strip IPv4-mapped IPv6 prefix (::ffff:10.0.0.1 → 10.0.0.1)
                ip = v.replace("::ffff:", "").strip()
                if ip and ip != "-":
                    ips.add(ip)
    return list(ips)


def _first(events: List[Dict]) -> str:
    ts = [e.get("timestamp", _now()) for e in events]
    return min(ts) if ts else _now()


def _last(events: List[Dict]) -> str:
    ts = [e.get("timestamp", _now()) for e in events]
    return max(ts) if ts else _now()


# RC4 encryption type (0x17) — weak, targeted by Kerberoasting
_RC4 = "0x17"


RULES = [
    {
        "id": "DET-001",
        "name": "Kerberoasting — Bulk TGS Requests",
        "severity": "high",
        "mitre_id": "T1558.003",
        "mitre_technique": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "description": (
            "Multiple EventID 4769 (Kerberos TGS requests) targeting different SPNs from a "
            "single source IP — especially with RC4 encryption (0x17) — indicating offline "
            "hash harvesting for password cracking."
        ),
        "triage_steps": [
            "Identify the source IP and correlate with the SubjectUserName in Event 4769",
            "Check TicketEncryptionType: RC4 (0x17) requests are a strong indicator — modern systems use AES (0x12/0x11)",
            "Review which SPNs were targeted; prioritise any belonging to privileged service accounts",
            "Search for subsequent lateral movement or pass-the-hash attempts from the same IP",
            "Rotate passwords on affected service accounts to 25+ character random strings and enforce AES-only ticket policy",
        ],
        "match": lambda events: [
            e for e in events
            if e.get("EventID") == 4769
            and not e.get("is_baseline")
            and not e.get("attack") == "A5"  # exclude ACL abuse TGS (handled by DET-005)
        ],
        "threshold": 2,
        "confidence_fn": lambda matched: min(0.97, 0.55 + len(matched) * 0.12 + (
            0.15 if any(e.get("TicketEncryptionType") == _RC4 for e in matched) else 0
        )),
    },
    {
        "id": "DET-002",
        "name": "AS-REP Roasting — Pre-Auth Disabled Accounts",
        "severity": "high",
        "mitre_id": "T1558.004",
        "mitre_technique": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        "description": (
            "EventID 4768 with PreAuthType 0 — Kerberos TGT requests for accounts with "
            "pre-authentication disabled. The KDC returns an encrypted TGT without validating "
            "identity, exposing crackable AS-REP hashes to unauthenticated attackers."
        ),
        "triage_steps": [
            "Run: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} to enumerate all vulnerable accounts",
            "Determine if the ClientAddress is a known asset — anonymous AS-REP requests are always suspicious",
            "Enable Kerberos pre-authentication (DONT_REQ_PREAUTH) on all identified accounts immediately",
            "Force password reset on targeted accounts and audit group memberships for privilege escalation",
            "Review preceding LDAP queries (EventID 4662/1644) for domain enumeration by the same source",
        ],
        "match": lambda events: [
            e for e in events
            if e.get("EventID") == 4768
            and e.get("PreAuthType") == "0"
        ],
        "threshold": 1,
        "confidence_fn": lambda matched: 0.93 if matched else 0,
    },
    {
        "id": "DET-003",
        "name": "Password Spray — Distributed Auth Failures",
        "severity": "medium",
        "mitre_id": "T1110.003",
        "mitre_technique": "Brute Force: Password Spraying",
        "description": (
            "Multiple EventID 4625 (logon failures) with Status 0xC000006D/SubStatus 0xC000006A "
            "across 3+ distinct accounts from a single IpAddress with zero successes — "
            "classic low-and-slow password spray pattern designed to evade lockout policies."
        ),
        "triage_steps": [
            "Block the source IpAddress at the firewall/NAC and check for VPN/proxy masking",
            "Query EventID 4624 (successful logon) from the same IP — any success means account compromise",
            "Review EventID 4740 (account lockout) for any accounts already locked from this spray",
            "Cross-reference TargetUserName values against high-privilege accounts (Domain Admins, service accounts)",
            "Enforce MFA on all accounts and review conditional access policies immediately",
        ],
        "match": lambda events: [
            e for e in events
            if e.get("EventID") == 4625
            and e.get("Status") == "0xC000006D"
            and not e.get("is_baseline")
        ],
        "threshold": 3,
        "confidence_fn": lambda matched: min(0.92, 0.40 + (
            len({e.get("TargetUserName", "") for e in matched}) * 0.10
        )),
    },
    {
        "id": "DET-004",
        "name": "DCSync — Replication from Non-DC Host",
        "severity": "critical",
        "mitre_id": "T1003.006",
        "mitre_technique": "OS Credential Dumping: DCSync",
        "description": (
            "EventID 4662 with DS-Replication GUIDs ({1131f6aa...}, {1131f6ab...}) originating "
            "from a machine that is not a domain controller. Tools like Mimikatz and Impacket "
            "secretsdump use this technique to extract all domain password hashes without touching LSASS."
        ),
        "triage_steps": [
            "Immediately isolate the source machine (IpAddress in the event) from the network",
            "Treat all domain credentials as compromised — initiate a domain-wide password reset",
            "Reset KRBTGT password twice with a 10-hour delay to invalidate existing Kerberos tickets and Golden Tickets",
            "Investigate SubjectUserName for privilege escalation path — how did this account get replication rights?",
            "Conduct memory and disk forensics on the source machine for Mimikatz, Cobalt Strike, or similar tooling",
        ],
        "match": lambda events: [
            e for e in events
            if e.get("EventID") == 4662
            and e.get("IsNonDCSource") is True
            and "{1131f6aa" in e.get("Properties", "")
        ],
        "threshold": 1,
        "confidence_fn": lambda matched: 0.98 if matched else 0,
    },
    {
        "id": "DET-005",
        "name": "ACL Abuse — Targeted SPN Write then Kerberoast",
        "severity": "critical",
        "mitre_id": "T1484.001",
        "mitre_technique": "Domain Policy Modification: Group Policy Modification",
        "description": (
            "EventID 4738 (account modified: ServicePrincipalName) followed by EventID 4769 "
            "(TGS request) from the same SubjectUserName — indicates GenericWrite/WriteSPN "
            "ACL abuse to register a rogue SPN on a target account and immediately Kerberoast it."
        ),
        "triage_steps": [
            "Revoke GenericWrite / WriteSPN permissions for SubjectUserName on all AD objects immediately",
            "Remove the maliciously added SPN (ServicePrincipalName in Event 4738) from the target account",
            "Rotate password on the target service account (TargetUserName in Event 4738)",
            "Run BloodHound or PowerView to map all excessive ACL permissions across the domain",
            "Review EventID 4662/5136 for other recent attribute modifications by the same actor",
        ],
        "match": lambda events: (
            lambda writes, tgs: writes + tgs if (
                writes and tgs and
                any(
                    w.get("SubjectUserName") == t.get("SubjectUserName")
                    for w in writes for t in tgs
                )
            ) else []
        )(
            [e for e in events if e.get("EventID") == 4738 and e.get("ChangedAttributes") == "ServicePrincipalName"],
            [e for e in events if e.get("EventID") == 4769 and e.get("attack") == "A5"],
        ),
        "threshold": 1,
        "confidence_fn": lambda matched: 0.97 if len(matched) >= 2 else 0,
    },
]


def run_detections(events: List[Dict]) -> List[Alert]:
    alerts = []
    for rule in RULES:
        matched = rule["match"](events)
        if len(matched) >= rule["threshold"]:
            confidence = rule["confidence_fn"](matched)
            if confidence > 0:
                alerts.append(Alert(
                    id=str(uuid.uuid4()),
                    rule_id=rule["id"],
                    name=rule["name"],
                    severity=rule["severity"],
                    mitre_id=rule["mitre_id"],
                    mitre_technique=rule["mitre_technique"],
                    description=rule["description"],
                    confidence=round(confidence, 2),
                    matched_event_count=len(matched),
                    affected_accounts=_accounts(matched),
                    affected_ips=_ips(matched),
                    first_seen=_first(matched),
                    last_seen=_last(matched),
                    triage_steps=rule["triage_steps"],
                    matched_events=matched[:10],
                ))
    return alerts
