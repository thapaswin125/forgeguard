import random
import time
from datetime import datetime, timezone
from typing import List, Dict

# --- Realistic AD environment ---
DOMAIN = "CORP.CONTOSO.COM"
DOMAIN_SHORT = "CORP"
DC_FQDN = "DC01.CORP.CONTOSO.COM"
DC_IP = "10.0.0.1"
DC_SID = "S-1-5-21-3623811015-3361044348-30300820"

USERS = [
    {"name": "j.smith",    "sid": f"{DC_SID}-1105", "display": "John Smith"},
    {"name": "a.jones",    "sid": f"{DC_SID}-1106", "display": "Amy Jones"},
    {"name": "m.patel",    "sid": f"{DC_SID}-1107", "display": "Mike Patel"},
    {"name": "k.wilson",   "sid": f"{DC_SID}-1108", "display": "Karen Wilson"},
    {"name": "r.chen",     "sid": f"{DC_SID}-1109", "display": "Ray Chen"},
    {"name": "t.nguyen",   "sid": f"{DC_SID}-1110", "display": "Tina Nguyen"},
    {"name": "s.roberts",  "sid": f"{DC_SID}-1111", "display": "Sam Roberts"},
    {"name": "d.kim",      "sid": f"{DC_SID}-1112", "display": "Dana Kim"},
    {"name": "l.garcia",   "sid": f"{DC_SID}-1113", "display": "Luis Garcia"},
    {"name": "b.thompson", "sid": f"{DC_SID}-1114", "display": "Beth Thompson"},
]

SERVICE_ACCOUNTS = [
    {"name": "svc_sql",     "sid": f"{DC_SID}-1200", "spn": "MSSQLSvc/SQL01.CORP.CONTOSO.COM:1433"},
    {"name": "svc_web",     "sid": f"{DC_SID}-1201", "spn": "HTTP/WEB01.CORP.CONTOSO.COM"},
    {"name": "svc_backup",  "sid": f"{DC_SID}-1202", "spn": "HOST/BACKUP01.CORP.CONTOSO.COM"},
    {"name": "svc_monitor", "sid": f"{DC_SID}-1203", "spn": "MONITORING/MON01.CORP.CONTOSO.COM"},
]

WORKSTATIONS = [f"WRK-{i:03d}" for i in range(1, 11)]
SERVERS = ["SQL01", "WEB01", "BACKUP01", "MON01", "FS01"]
ATTACKER_IPS = ["10.0.0.50", "10.0.0.51", "192.168.1.99"]
NORMAL_IPS = ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"]

# Real Windows Kerberos encryption type codes
ENC_RC4 = "0x17"      # RC4-HMAC (weak, targeted by Kerberoasting)
ENC_AES256 = "0x12"   # AES256-CTS-HMAC-SHA1-96
ENC_AES128 = "0x11"   # AES128-CTS-HMAC-SHA1-96

# Real Windows logon failure status codes
STATUS_WRONG_PASSWORD = "0xC000006A"
STATUS_BAD_USERNAME = "0xC0000064"
STATUS_LOGON_FAILURE = "0xC000006D"


def _ts(offset: float = 0) -> str:
    return datetime.fromtimestamp(time.time() + offset, tz=timezone.utc).isoformat()


def _logon_id() -> str:
    return hex(random.randint(0x100000, 0xFFFFFF))


def _port() -> str:
    return str(random.randint(49152, 65535))


def _wrk_fqdn(name: str) -> str:
    return f"{name}.{DOMAIN}"


# ── Baseline: normal Kerberos/LDAP traffic ─────────────────────────────────

def generate_baseline() -> List[Dict]:
    events = []
    for _ in range(50):
        user = random.choice(USERS)
        src_ip = random.choice(NORMAL_IPS)
        wrk = random.choice(WORKSTATIONS)
        events.append({
            "EventID": 4769,
            "EventName": "A Kerberos service ticket was requested",
            "timestamp": _ts(random.uniform(-300, 0)),
            "Computer": DC_FQDN,
            "SubjectUserName": user["name"],
            "SubjectDomainName": DOMAIN_SHORT,
            "SubjectLogonId": _logon_id(),
            "SubjectUserSid": user["sid"],
            "ServiceName": random.choice(SERVICE_ACCOUNTS)["spn"],
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": random.choice([ENC_AES256, ENC_AES128]),
            "ClientAddress": f"::ffff:{src_ip}",
            "ClientPort": _port(),
            "Workstation": _wrk_fqdn(wrk),
            "auth_result": "SUCCESS",
            "is_baseline": True,
        })
    return events


# ── A1: Kerberoasting (EventID 4769) ───────────────────────────────────────

def simulate_kerberoasting(stealth: int = 0) -> List[Dict]:
    events = []
    src_ip = random.choice(ATTACKER_IPS)
    user = random.choice(USERS)
    logon_id = _logon_id()
    delay = 0.8 if stealth else 0.05

    for i, svc in enumerate(SERVICE_ACCOUNTS):
        events.append({
            "EventID": 4769,
            "EventName": "A Kerberos service ticket was requested",
            "timestamp": _ts(i * delay),
            "Computer": DC_FQDN,
            "SubjectUserName": user["name"],
            "SubjectDomainName": DOMAIN_SHORT,
            "SubjectLogonId": logon_id,
            "SubjectUserSid": user["sid"],
            "ServiceName": svc["spn"],
            "ServiceSid": svc["sid"],
            "TicketOptions": "0x40800000",
            # Attackers request RC4 for offline cracking compatibility
            "TicketEncryptionType": random.choice([ENC_RC4, ENC_RC4, ENC_AES256]),
            "ClientAddress": f"::ffff:{src_ip}",
            "ClientPort": _port(),
            "Workstation": f"KALI-{src_ip.split('.')[-1]}",
            "attack": "A1",
        })
    return events


# ── A2: AS-REP Roasting (EventID 4768) ─────────────────────────────────────

def simulate_asrep_roasting(stealth: int = 0) -> List[Dict]:
    events = []
    src_ip = random.choice(ATTACKER_IPS)
    targets = random.sample(SERVICE_ACCOUNTS, 2)
    delay = 2.0 if stealth else 0.1

    for i, svc in enumerate(targets):
        events.append({
            "EventID": 4768,
            "EventName": "A Kerberos authentication ticket (TGT) was requested",
            "timestamp": _ts(i * delay),
            "Computer": DC_FQDN,
            "TargetUserName": svc["name"],
            "TargetDomainName": DOMAIN_SHORT,
            "TargetSid": svc["sid"],
            "TicketOptions": "0x40810010",
            "TicketEncryptionType": ENC_RC4,
            "PreAuthType": "0",       # 0 = no pre-authentication (exploitable)
            "Status": "0x0",          # Success — hash returned
            "ClientAddress": f"::ffff:{src_ip}",
            "ClientPort": _port(),
            # AS-REP hash stub matching real hashcat format
            "CapturedHash": f"$krb5asrep$23${svc['name']}@{DOMAIN}:{'a' * 32}:{'b' * 64}",
            "attack": "A2",
        })
    return events


# ── A3: Password Spray (EventID 4625) ──────────────────────────────────────

def simulate_password_spray(stealth: int = 0) -> List[Dict]:
    events = []
    src_ip = random.choice(ATTACKER_IPS)
    targets = random.sample(USERS, min(8, len(USERS)))
    delay = 30.0 if stealth else 2.0   # slow spray vs fast spray

    for i, user in enumerate(targets):
        events.append({
            "EventID": 4625,
            "EventName": "An account failed to log on",
            "timestamp": _ts(i * delay),
            "Computer": DC_FQDN,
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "TargetUserName": user["name"],
            "TargetDomainName": DOMAIN_SHORT,
            "Status": STATUS_LOGON_FAILURE,
            "SubStatus": STATUS_WRONG_PASSWORD,
            "LogonType": 3,            # Network logon
            "LogonProcessName": "NtLmSsp",
            "AuthPackageName": "NTLM",
            "WorkstationName": "-",
            "IpAddress": src_ip,
            "IpPort": "0",
            "FailureReason": "%%2313",  # Unknown username or bad password
            "attack": "A3",
        })
    return events


# ── A4: DCSync (EventID 4662) ───────────────────────────────────────────────

def simulate_dcsync(stealth: int = 0) -> List[Dict]:
    src_ip = random.choice(ATTACKER_IPS)
    user = random.choice(USERS)

    # Real DS-Replication GUIDs used by Mimikatz/Impacket dcsync
    replication_guids = [
        "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",  # DS-Replication-Get-Changes
        "{1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}",  # DS-Replication-Get-Changes-All
        "{89e95b76-444d-4c62-991a-0facbeda640c}",  # DS-Replication-Get-Changes-In-Filtered-Set
    ]

    return [{
        "EventID": 4662,
        "EventName": "An operation was performed on an object",
        "timestamp": _ts(),
        "Computer": DC_FQDN,
        "SubjectUserSid": user["sid"],
        "SubjectUserName": user["name"],
        "SubjectDomainName": DOMAIN_SHORT,
        "SubjectLogonId": _logon_id(),
        "ObjectServer": "DS",
        "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",  # domainDNS
        "ObjectName": f"DC=corp,DC=contoso,DC=com",
        "OperationType": "Object Access",
        "AccessMask": "0x100",
        "Properties": " ".join(replication_guids),
        "AdditionalInfo": "{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
        "IpAddress": src_ip,
        "IpPort": _port(),
        "IsNonDCSource": True,          # key detection field
        "RequestingMachine": src_ip,
        "TargetDC": DC_IP,
        "ReplicatedAttributes": ["unicodePwd", "ntPwdHistory", "supplementalCredentials"],
        "attack": "A4",
    }]


# ── A5: ACL Abuse — SPN Write + Kerberoast (EventID 4738 + 4769) ───────────

def simulate_acl_abuse(stealth: int = 0) -> List[Dict]:
    actor = random.choice(USERS)
    target_svc = random.choice(SERVICE_ACCOUNTS)
    evil_spn = f"HTTP/evil.{DOMAIN.lower()}"
    src_ip = random.choice(ATTACKER_IPS)
    delay = 10.0 if stealth else 1.5

    spn_write = {
        "EventID": 4738,
        "EventName": "A user account was changed",
        "timestamp": _ts(0),
        "Computer": DC_FQDN,
        "SubjectUserSid": actor["sid"],
        "SubjectUserName": actor["name"],
        "SubjectDomainName": DOMAIN_SHORT,
        "SubjectLogonId": _logon_id(),
        "TargetUserName": target_svc["name"],
        "TargetDomainName": DOMAIN_SHORT,
        "TargetSid": target_svc["sid"],
        "ChangedAttributes": "ServicePrincipalName",
        "ServicePrincipalName": evil_spn,
        "PreviousSPN": target_svc["spn"],
        "IpAddress": src_ip,
        "IpPort": _port(),
        "attack": "A5",
    }

    tgs_req = {
        "EventID": 4769,
        "EventName": "A Kerberos service ticket was requested",
        "timestamp": _ts(delay),
        "Computer": DC_FQDN,
        "SubjectUserName": actor["name"],
        "SubjectDomainName": DOMAIN_SHORT,
        "SubjectLogonId": _logon_id(),
        "SubjectUserSid": actor["sid"],
        "ServiceName": evil_spn,
        "ServiceSid": target_svc["sid"],
        "TicketOptions": "0x40800000",
        "TicketEncryptionType": ENC_RC4,
        "ClientAddress": f"::ffff:{src_ip}",
        "ClientPort": _port(),
        "attack": "A5",
    }

    return [spn_write, tgs_req]


# ── Scenario registry ───────────────────────────────────────────────────────

SCENARIOS = {
    "A1": {"fn": simulate_kerberoasting, "name": "Kerberoasting",     "mitre": "T1558.003"},
    "A2": {"fn": simulate_asrep_roasting, "name": "AS-REP Roasting",  "mitre": "T1558.004"},
    "A3": {"fn": simulate_password_spray, "name": "Password Spray",   "mitre": "T1110.003"},
    "A4": {"fn": simulate_dcsync,          "name": "DCSync",           "mitre": "T1003.006"},
    "A5": {"fn": simulate_acl_abuse,       "name": "ACL Abuse Chain",  "mitre": "T1484.001"},
}


def run_scenario(scenario_id: str, stealth: int = 0) -> List[Dict]:
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    baseline = generate_baseline()
    attack_events = SCENARIOS[scenario_id]["fn"](stealth)
    return baseline + attack_events
