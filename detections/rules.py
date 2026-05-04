from dataclasses import dataclass, field
from typing import List, Dict, Callable
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
        for f in ["username", "actor_username", "target_account"]:
            if e.get(f):
                accts.add(e[f])
    return list(accts)


def _ips(events: List[Dict]) -> List[str]:
    return list({e.get("src_ip", "") for e in events if e.get("src_ip")})


def _first(events: List[Dict]) -> str:
    ts = [e.get("timestamp", _now()) for e in events]
    return min(ts) if ts else _now()


def _last(events: List[Dict]) -> str:
    ts = [e.get("timestamp", _now()) for e in events]
    return max(ts) if ts else _now()


RULES = [
    {
        "id": "DET-001",
        "name": "Kerberoasting — Bulk TGS Requests",
        "severity": "high",
        "mitre_id": "T1558.003",
        "mitre_technique": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "description": "Multiple TGS requests targeting different SPNs from a single source IP, often with RC4 encryption, indicating ticket harvesting for offline cracking.",
        "triage_steps": [
            "Identify the source IP and correlated user account",
            "Check if RC4 encryption was requested — modern systems prefer AES; RC4 requests are suspicious",
            "Review which SPNs were targeted and whether they belong to privileged service accounts",
            "Check for subsequent offline hash cracking activity or lateral movement from the same IP",
            "Consider rotating passwords on affected service accounts and enforcing AES-only tickets"
        ],
        "match": lambda events: [
            e for e in events
            if e.get("event_type") == "TGS_REQ" and not e.get("is_baseline")
        ],
        "threshold": 2,
        "confidence_fn": lambda matched: min(0.95, 0.5 + len(matched) * 0.15)
    },
    {
        "id": "DET-002",
        "name": "AS-REP Roasting — Pre-Auth Disabled Accounts",
        "severity": "high",
        "mitre_id": "T1558.004",
        "mitre_technique": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        "description": "AS-REQ requests for accounts with Kerberos pre-authentication disabled, exposing password hashes without credentials.",
        "triage_steps": [
            "Identify all accounts with pre-authentication disabled in the domain",
            "Determine if the requesting IP is a known asset or unauthorized host",
            "Enable pre-authentication on all non-legacy accounts immediately",
            "Force password reset on targeted accounts",
            "Audit LDAP query logs for reconnaissance activity preceding this event"
        ],
        "match": lambda events: [
            e for e in events
            if e.get("event_type") == "AS_REQ" and e.get("pre_auth_enabled") is False
        ],
        "threshold": 1,
        "confidence_fn": lambda matched: 0.92 if matched else 0
    },
    {
        "id": "DET-003",
        "name": "Password Spray — Low-and-Slow Auth Failures",
        "severity": "medium",
        "mitre_id": "T1110.003",
        "mitre_technique": "Brute Force: Password Spraying",
        "description": "Single source IP producing authentication failures across multiple distinct accounts with no successes — classic password spray pattern.",
        "triage_steps": [
            "Block the source IP at the firewall or NAC immediately",
            "Audit all accounts targeted for any successful logins from the same IP",
            "Check for VPN or proxy usage at the source IP to identify evasion",
            "Review Active Directory lockout logs for affected accounts",
            "Enforce MFA across all user accounts if not already in place"
        ],
        "match": lambda events: [
            e for e in events
            if e.get("event_type") == "LDAP_BIND"
            and e.get("auth_result") == "FAILURE"
            and not e.get("is_baseline")
        ],
        "threshold": 3,
        "confidence_fn": lambda matched: min(0.9, 0.4 + len(set(e.get("username","") for e in matched)) * 0.1)
    },
    {
        "id": "DET-004",
        "name": "DCSync — Replication from Non-DC Host",
        "severity": "critical",
        "mitre_id": "T1003.006",
        "mitre_technique": "OS Credential Dumping: DCSync",
        "description": "Directory replication request originated from a machine that is not a domain controller — a hallmark of DCSync credential dumping attacks.",
        "triage_steps": [
            "Immediately isolate the source machine from the network",
            "Assume all domain credentials are compromised — initiate domain-wide password reset",
            "Reset the KRBTGT account password twice (required to invalidate existing golden tickets)",
            "Review which accounts' credentials were replicated",
            "Conduct forensic analysis on the source machine for malware and persistence mechanisms"
        ],
        "match": lambda events: [
            e for e in events
            if e.get("event_type") == "REPLICATION_REQ"
            and e.get("is_domain_controller") is False
        ],
        "threshold": 1,
        "confidence_fn": lambda matched: 0.98 if matched else 0
    },
    {
        "id": "DET-005",
        "name": "ACL Abuse — SPN Write Followed by TGS Request",
        "severity": "critical",
        "mitre_id": "T1484.001",
        "mitre_technique": "Domain Policy Modification: Group Policy Modification",
        "description": "A user account modified the servicePrincipalName attribute of another account and immediately requested a TGS ticket for it — a targeted ACL abuse to Kerberoast a specific account.",
        "triage_steps": [
            "Identify the actor account and revoke its GenericWrite or WriteSPN permissions immediately",
            "Remove the maliciously added SPN from the target account",
            "Rotate the password on the target service account",
            "Audit all ACL permissions on privileged accounts for excessive rights",
            "Review AD audit logs for other attribute modifications by the same actor"
        ],
        "match": lambda events: (
            lambda writes, tgs: writes + tgs if (
                writes and tgs and
                any(w.get("actor_username") == t.get("username") for w in writes for t in tgs)
            ) else []
        )(
            [e for e in events if e.get("event_type") == "LDAP_WRITE" and e.get("modified_attribute") == "servicePrincipalName"],
            [e for e in events if e.get("event_type") == "TGS_REQ" and not e.get("is_baseline")]
        ),
        "threshold": 1,
        "confidence_fn": lambda matched: 0.97 if len(matched) >= 2 else 0
    }
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
                    matched_events=matched[:10]
                ))
    return alerts
