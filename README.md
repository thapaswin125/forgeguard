# ForgeGuard — Active Directory Blue Team Lab

ForgeGuard is a detection engineering workbench that simulates real Active Directory attacks, fires detection rules against them in real time, and generates AI-powered triage runbooks using Groq (Llama 3.3 70B). Built for blue teamers and SOC analysts to practice detecting and responding to AD-based threats without needing a live domain.

```
┌─────────────────────────────────────────────────────────────┐
│                    ForgeGuard Architecture                  │
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  Simulator  │───▶│  Detection   │───▶│   SQLite DB   │  │
│  │  generator  │    │    Rules     │    │   (lab.db)    │  │
│  └─────────────┘    └──────────────┘    └───────┬───────┘  │
│                                                 │           │
│                                          ┌──────▼──────┐   │
│                                          │  FastAPI    │   │
│                                          │  Backend    │   │
│                                          └──────┬──────┘   │
│                                                 │           │
│                          ┌──────────────────────┤           │
│                          │                      │           │
│                   ┌──────▼──────┐    ┌──────────▼───────┐  │
│                   │    React    │    │  Runbook Gen     │  │
│                   │  Dashboard  │    │  (Groq / Llama)  │  │
│                   └─────────────┘    └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## What It Does

- **Simulates AD attacks** — generates realistic event logs for 5 common attack patterns
- **Fires detection rules** — maps events to MITRE ATT&CK techniques with confidence scoring
- **Live alert feed** — React dashboard polls every 5 seconds and shows alerts with severity, MITRE ID, and affected accounts
- **AI runbook generation** — one click generates a structured SOC triage guide via Groq (Llama 3.3 70B), covering IOCs, containment steps, evidence collection, and false positive checks
- **Runbook export** — download every runbook as a `.md` file

## Attack Scenarios

| ID | Attack | MITRE | Severity |
|----|--------|-------|----------|
| A1 | Kerberoasting | T1558.003 | High |
| A2 | AS-REP Roasting | T1558.004 | High |
| A3 | Password Spray | T1110.003 | Medium |
| A4 | DCSync | T1003.006 | Critical |
| A5 | ACL Abuse Chain | T1484.001 | Critical |

## Detection Rules

| Rule | What It Detects | MITRE ID |
|------|-----------------|----------|
| DET-001 | Bulk TGS requests from a single IP | T1558.003 |
| DET-002 | AS-REQ for pre-auth disabled accounts | T1558.004 |
| DET-003 | Auth failures across 3+ accounts, no successes | T1110.003 |
| DET-004 | Replication request from non-DC machine | T1003.006 |
| DET-005 | SPN write immediately followed by TGS request | T1484.001 |

## Setup

**1. Clone and configure**
```bash
git clone https://github.com/thapaswin125/forgeguard.git
cd forgeguard
cp .env.example .env
# Edit .env and add your GROQ_API_KEY (get one free at console.groq.com)
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
cd dashboard && npm install && cd ..
```

**3. Start the lab**
```bash
# Terminal 1 — API (port 8000)
python -m uvicorn api.main:app --reload --port 8000

# Terminal 2 — Dashboard (port 5173)
cd dashboard && npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

## Demo Walkthrough

1. Open the dashboard at [http://localhost:5173](http://localhost:5173)
2. Pick an attack scenario (e.g. **A4 — DCSync**), toggle Stealth if you want low-and-slow behavior, and click **Run Simulation**
3. Watch alerts appear in the live feed — each shows severity, MITRE technique, confidence score, and affected accounts
4. Click an alert to open the **Triage Drawer** — see matched raw events and quick triage steps
5. Click **Generate AI Runbook** — Groq (Llama 3.3 70B) produces a structured incident response guide in seconds
6. Download the `.md` runbook for your records or ticket system
7. Click **Reset Lab** to clear all alerts and start fresh

## Sample Runbook Output (DET-004 — DCSync)

> **Incident Summary:** A critical alert was triggered for a DCSync attack (T1003.006). A non-domain-controller host (10.0.0.51) sent replication requests for sensitive attributes including `unicodePwd` and `ntPwdHistory`, indicating likely credential dumping.
>
> **Immediate Containment:** Isolate 10.0.0.51, initiate domain-wide password reset, reset KRBTGT password twice.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Tailwind CSS |
| Backend | FastAPI, SQLite, Python 3.12 |
| AI | Groq API — Llama 3.3 70B |
| Attack Sim | Custom Python event generators |
| Detection | Rule engine with MITRE ATT&CK mapping |

## Environment Variables

```env
GROQ_API_KEY=gsk_...   # Free at console.groq.com
```
