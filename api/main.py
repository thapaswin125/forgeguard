import os
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "lab.db"

import sys
sys.path.insert(0, str(BASE_DIR))
from simulator.generator import SCENARIOS, run_scenario
from detections.rules import run_detections
from runbooks.generator import generate_runbook


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            rule_id TEXT,
            name TEXT,
            severity TEXT,
            mitre_id TEXT,
            mitre_technique TEXT,
            description TEXT,
            confidence REAL,
            matched_event_count INTEGER,
            affected_accounts TEXT,
            affected_ips TEXT,
            first_seen TEXT,
            last_seen TEXT,
            triage_steps TEXT,
            matched_events TEXT,
            scenario_id TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS runbooks (
            id TEXT PRIMARY KEY,
            alert_id TEXT,
            content TEXT,
            created_at TEXT
        );
    """)
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="ForgeGuard API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SimulateRequest(BaseModel):
    scenario_id: str
    stealth: Optional[int] = 0


@app.get("/api/scenarios")
def list_scenarios():
    return [
        {
            "id": sid,
            "name": s["name"],
            "mitre_id": s["mitre"],
            "description": _scenario_desc(sid)
        }
        for sid, s in SCENARIOS.items()
    ]


def _scenario_desc(sid):
    descs = {
        "A1": "Simulates bulk TGS ticket requests targeting all SPNs in the domain to harvest hashes for offline cracking.",
        "A2": "Queries accounts with Kerberos pre-authentication disabled and captures AS-REP hashes without credentials.",
        "A3": "Simulates low-and-slow password spray across multiple accounts from a single source IP.",
        "A4": "Mimics a DCSync attack by generating replication requests from a non-domain-controller machine.",
        "A5": "Exploits GenericWrite ACL permission to add an SPN to a target account, then Kerberoasts it."
    }
    return descs.get(sid, "")


@app.post("/api/simulate")
def simulate(req: SimulateRequest):
    if req.scenario_id not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {req.scenario_id}")

    events = run_scenario(req.scenario_id, req.stealth)
    alerts = run_detections(events)

    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    saved_alerts = []

    for alert in alerts:
        conn.execute("""
            INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            alert.id, alert.rule_id, alert.name, alert.severity,
            alert.mitre_id, alert.mitre_technique, alert.description,
            alert.confidence, alert.matched_event_count,
            json.dumps(alert.affected_accounts), json.dumps(alert.affected_ips),
            alert.first_seen, alert.last_seen,
            json.dumps(alert.triage_steps), json.dumps(alert.matched_events),
            req.scenario_id, now
        ))
        saved_alerts.append(alert.to_dict())

    conn.commit()
    conn.close()

    return {"alerts": saved_alerts, "events_processed": len(events)}


@app.get("/api/alerts")
def get_alerts():
    conn = get_db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    conn.close()
    return [_parse_alert_row(r) for r in rows]


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = _parse_alert_row(row)
    alert["matched_events"] = json.loads(row["matched_events"])
    return alert


@app.post("/api/alerts/{alert_id}/runbook")
def create_runbook(alert_id: str):
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(status_code=400, detail="ANTHROPIC_API_KEY not set in .env")

    conn = get_db()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = _parse_alert_row(row)
    matched_events = json.loads(row["matched_events"])

    try:
        runbook_content = generate_runbook(alert, matched_events)
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Runbook generation failed: {str(e)}")

    runbook_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO runbooks VALUES (?,?,?,?)",
                 (runbook_id, alert_id, runbook_content, now))
    conn.commit()
    conn.close()

    return {"id": runbook_id, "content": runbook_content}


@app.get("/api/stats")
def get_stats():
    conn = get_db()
    alerts = conn.execute("SELECT severity, mitre_id FROM alerts").fetchall()
    runbook_count = conn.execute("SELECT COUNT(*) FROM runbooks").fetchone()[0]
    conn.close()

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    techniques = set()
    for a in alerts:
        sev = a["severity"].lower()
        if sev in by_severity:
            by_severity[sev] += 1
        techniques.add(a["mitre_id"])

    return {
        "total_alerts": len(alerts),
        "alerts_by_severity": by_severity,
        "techniques_fired": list(techniques),
        "detection_coverage_pct": round(len(techniques) / 5 * 100),
        "runbooks_generated": runbook_count
    }


@app.delete("/api/reset")
def reset():
    conn = get_db()
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM runbooks")
    conn.commit()
    conn.close()
    return {"message": "Lab reset complete"}


def _parse_alert_row(row) -> dict:
    d = dict(row)
    for f in ["affected_accounts", "affected_ips", "triage_steps"]:
        if isinstance(d.get(f), str):
            d[f] = json.loads(d[f])
    d.pop("matched_events", None)
    return d
