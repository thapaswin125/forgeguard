import os
import json
from datetime import datetime, timezone
from pathlib import Path
import google.generativeai as genai

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def _build_prompt(alert: dict, matched_events: list) -> str:
    event_summary = []
    for e in matched_events[:8]:
        parts = []
        for k in ["timestamp", "event_type", "src_ip", "username", "actor_username",
                  "target_spn", "auth_result", "replicated_attributes", "new_spn_value"]:
            if e.get(k):
                val = json.dumps(e[k]) if isinstance(e[k], list) else e[k]
                parts.append(f"{k}: {val}")
        event_summary.append("  - " + " | ".join(parts))

    return f"""
ALERT DETAILS:
- Rule: {alert['rule_id']} — {alert['name']}
- Severity: {alert['severity'].upper()}
- MITRE Technique: {alert['mitre_id']} — {alert['mitre_technique']}
- Confidence: {int(alert['confidence'] * 100)}%
- Affected Accounts: {', '.join(alert['affected_accounts']) or 'Unknown'}
- Source IPs: {', '.join(alert['affected_ips']) or 'Unknown'}
- First Seen: {alert['first_seen']}
- Last Seen: {alert['last_seen']}
- Matched Events: {alert['matched_event_count']}

MATCHED EVENT LOG (sample):
{chr(10).join(event_summary)}

Write a triage runbook for a junior SOC analyst responding to this alert.
"""


def generate_runbook(alert: dict, matched_events: list) -> str:
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

    model = genai.GenerativeModel(
        model_name="gemini-1.5-pro",
        system_instruction="""You are a senior SOC analyst writing a concise, actionable triage runbook for a junior analyst.
Be specific, practical, and direct. Use plain English. No unnecessary jargon.

Structure your response EXACTLY as follows with these markdown headers:
## Incident Summary
## Indicators of Compromise (IOCs)
## What Likely Happened
## Immediate Containment Steps
## Evidence to Collect
## False Positive Check"""
    )

    prompt = _build_prompt(alert, matched_events)
    response = model.generate_content(prompt)
    runbook_text = response.text

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    alert_id_short = alert['id'][:8]
    filename = OUTPUT_DIR / f"{alert['rule_id']}_{alert_id_short}_{timestamp}.md"

    header = f"""# ForgeGuard Runbook — {alert['name']}
**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}  
**Alert ID:** {alert['id']}  
**Severity:** {alert['severity'].upper()}  
**MITRE:** [{alert['mitre_id']}](https://attack.mitre.org/techniques/{alert['mitre_id'].replace('.', '/')})

---

"""
    full_runbook = header + runbook_text

    with open(filename, "w") as f:
        f.write(full_runbook)

    return full_runbook
