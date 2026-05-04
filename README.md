# ForgeGuard — Active Directory Blue Team Lab

ForgeGuard is a detection engineering workbench that simulates real Active Directory attacks, fires detection rules against them in real time, and generates AI-powered triage runbooks. Built for blue teamers and SOC analysts to practice detecting and responding to AD-based threats without needing a live domain.

```
┌─────────────────────────────────────────────────────────────┐
│                      ForgeGuard Architecture                │
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
│                   │  Dashboard  │    │  (Claude API)    │  │
│                   └─────────────┘    └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Setup

**1. Clone and configure**
```bash
git clone <your-repo>
cd forgeguard
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
cd dashboard && npm install && cd ..
```

**3. Start the lab**
```bash
# Terminal 1 — API
uvicorn api.main:app --reload

# Terminal 2 — Dashboard
cd dashboard && npm run dev
```

Open http://localhost:5173 in your browser.

## Attack Scenarios

| ID | Attack | MITRE | Severity |
|----|--------|-------|----------|
| A1 | Kerberoasting | T1558.003 | High |
| A2 | AS-REP Roasting | T1558.004 | High |
| A3 | Password Spray | T1110.003 | Medium |
| A4 | DCSync | T1003.006 | Critical |
| A5 | ACL Abuse Chain | T1484.001 | Critical |

## Demo Walkthrough

1. Open the dashboard at http://localhost:5173
2. Click **Run Simulation** on **A1 — Kerberoasting** (Noisy mode)
3. Watch the alert appear in the feed within seconds
4. Click the alert to open the triage drawer
5. Click **Generate AI Runbook** — ForgeGuard calls Claude to produce a plain-English incident response guide
6. Download the `.md` runbook for your records

## Detection Coverage

| Rule | Technique | MITRE ID |
|------|-----------|----------|
| DET-001 | Bulk TGS requests from single IP | T1558.003 |
| DET-002 | AS-REQ for pre-auth disabled accounts | T1558.004 |
| DET-003 | Auth failures across 3+ accounts, no successes | T1110.003 |
| DET-004 | Replication request from non-DC machine | T1003.006 |
| DET-005 | SPN write immediately followed by TGS request | T1484.001 |
