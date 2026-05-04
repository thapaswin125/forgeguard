import random
import time
from datetime import datetime, timezone
from typing import List, Dict

USERNAMES = [
    "j.smith", "a.jones", "m.patel", "k.wilson", "r.chen",
    "t.nguyen", "s.roberts", "d.kim", "l.garcia", "b.thompson"
]
SERVICE_ACCOUNTS = ["svc_sql", "svc_web", "svc_backup", "svc_monitor"]
SPNS = [
    "MSSQLSvc/db01.lab.local:1433",
    "HTTP/webserver.lab.local",
    "HOST/backup01.lab.local",
    "MONITORING/monitor.lab.local"
]
DOMAIN_ADMIN = "da_admin"
SOURCE_IPS = ["10.0.0.50", "10.0.0.51", "192.168.1.99"]
DC_IP = "10.0.0.1"


def _ts(offset: float = 0) -> str:
    return datetime.fromtimestamp(time.time() + offset, tz=timezone.utc).isoformat()


def generate_baseline() -> List[Dict]:
    events = []
    for _ in range(50):
        events.append({
            "timestamp": _ts(random.uniform(-300, 0)),
            "event_type": random.choice(["LDAP_BIND", "TGT_REQ", "SERVICE_ACCESS"]),
            "src_ip": random.choice(["10.0.0.10", "10.0.0.11", "10.0.0.12"]),
            "username": random.choice(USERNAMES),
            "auth_result": "SUCCESS",
            "is_baseline": True
        })
    return events


def simulate_kerberoasting(stealth: int = 0) -> List[Dict]:
    events = []
    src_ip = random.choice(SOURCE_IPS)
    delay = 0.5 if stealth == 1 else 0
    for i, spn in enumerate(SPNS):
        events.append({
            "timestamp": _ts(i * delay),
            "event_type": "TGS_REQ",
            "src_ip": src_ip,
            "username": random.choice(USERNAMES),
            "target_spn": spn,
            "ticket_encryption_type": random.choice(["RC4-HMAC", "RC4-HMAC", "AES256"]),
            "attack": "A1"
        })
    return events


def simulate_asrep_roasting(stealth: int = 0) -> List[Dict]:
    events = []
    src_ip = random.choice(SOURCE_IPS)
    targets = random.sample(SERVICE_ACCOUNTS, 2)
    for i, acct in enumerate(targets):
        events.append({
            "timestamp": _ts(i * (1 if stealth else 0)),
            "event_type": "AS_REQ",
            "src_ip": src_ip,
            "username": acct,
            "pre_auth_enabled": False,
            "response_hash_stub": f"$krb5asrep$23${acct}@LAB.LOCAL:{'a'*32}",
            "attack": "A2"
        })
    return events


def simulate_password_spray(stealth: int = 0) -> List[Dict]:
    events = []
    src_ip = random.choice(SOURCE_IPS)
    targets = random.sample(USERNAMES, min(8, len(USERNAMES)))
    for i, user in enumerate(targets):
        events.append({
            "timestamp": _ts(i * (30 if stealth else 2)),
            "event_type": "LDAP_BIND",
            "src_ip": src_ip,
            "username": user,
            "auth_result": "FAILURE",
            "failure_reason": "WRONG_PASSWORD",
            "attack": "A3"
        })
    return events


def simulate_dcsync(stealth: int = 0) -> List[Dict]:
    src_ip = random.choice(SOURCE_IPS)
    return [{
        "timestamp": _ts(),
        "event_type": "REPLICATION_REQ",
        "src_ip": src_ip,
        "requesting_machine": src_ip,
        "is_domain_controller": False,
        "replicated_attributes": ["unicodePwd", "ntPwdHistory", "supplementalCredentials"],
        "target_dc": DC_IP,
        "attack": "A4"
    }]


def simulate_acl_abuse(stealth: int = 0) -> List[Dict]:
    actor = random.choice(USERNAMES)
    target_acct = random.choice(SERVICE_ACCOUNTS)
    new_spn = f"HTTP/evil.lab.local"
    src_ip = random.choice(SOURCE_IPS)
    delay = 5 if stealth else 1
    return [
        {
            "timestamp": _ts(0),
            "event_type": "LDAP_WRITE",
            "src_ip": src_ip,
            "actor_username": actor,
            "target_account": target_acct,
            "modified_attribute": "servicePrincipalName",
            "new_spn_value": new_spn,
            "attack": "A5"
        },
        {
            "timestamp": _ts(delay),
            "event_type": "TGS_REQ",
            "src_ip": src_ip,
            "username": actor,
            "target_spn": new_spn,
            "ticket_encryption_type": "RC4-HMAC",
            "attack": "A5"
        }
    ]


SCENARIOS = {
    "A1": {"fn": simulate_kerberoasting, "name": "Kerberoasting", "mitre": "T1558.003"},
    "A2": {"fn": simulate_asrep_roasting, "name": "AS-REP Roasting", "mitre": "T1558.004"},
    "A3": {"fn": simulate_password_spray, "name": "Password Spray", "mitre": "T1110.003"},
    "A4": {"fn": simulate_dcsync, "name": "DCSync", "mitre": "T1003.006"},
    "A5": {"fn": simulate_acl_abuse, "name": "ACL Abuse Chain", "mitre": "T1484.001"},
}


def run_scenario(scenario_id: str, stealth: int = 0) -> List[Dict]:
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    baseline = generate_baseline()
    attack_events = SCENARIOS[scenario_id]["fn"](stealth)
    return baseline + attack_events
