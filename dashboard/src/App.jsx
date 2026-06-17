import { useState, useEffect, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'

const API = '/api'

const SEV_STYLES = {
  critical: 'bg-red-900/40 text-red-300 border border-red-700/50',
  high:     'bg-orange-900/40 text-orange-300 border border-orange-700/50',
  medium:   'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',
  low:      'bg-blue-900/40 text-blue-300 border border-blue-700/50',
}

const SEV_DOT = {
  critical: 'bg-red-400',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
}

const MITRE_COLORS = {
  'T1558.003': 'bg-purple-900/40 text-purple-300',
  'T1558.004': 'bg-purple-900/40 text-purple-300',
  'T1110.003': 'bg-blue-900/40 text-blue-300',
  'T1003.006': 'bg-red-900/40 text-red-300',
  'T1484.001': 'bg-pink-900/40 text-pink-300',
}

function StatCard({ label, value, color = 'text-white' }) {
  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
      <p className="text-xs text-slate-400 mb-1">{label}</p>
      <p className={`text-2xl font-semibold ${color}`}>{value}</p>
    </div>
  )
}

function SeverityBadge({ severity }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SEV_STYLES[severity] || SEV_STYLES.low}`}>
      {severity.toUpperCase()}
    </span>
  )
}

function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100)
  const color = pct >= 90 ? 'bg-red-400' : pct >= 70 ? 'bg-orange-400' : 'bg-yellow-400'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400 w-8">{pct}%</span>
    </div>
  )
}

function ScenarioCard({ scenario, onRun }) {
  const [stealth, setStealth] = useState(0)
  const [loading, setLoading] = useState(false)
  const [ran, setRan] = useState(false)

  const handleRun = async () => {
    setLoading(true)
    try {
      await onRun(scenario.id, stealth)
      setRan(true)
      setTimeout(() => setRan(false), 3000)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4 flex flex-col gap-3">
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs font-mono text-slate-500">{scenario.id}</span>
          <span className={`text-xs px-2 py-0.5 rounded font-mono ${MITRE_COLORS[scenario.mitre_id] || 'bg-slate-700 text-slate-300'}`}>
            {scenario.mitre_id}
          </span>
        </div>
        <p className="text-sm font-medium text-white">{scenario.name}</p>
        <p className="text-xs text-slate-400 mt-1 leading-relaxed">{scenario.description}</p>
      </div>
      <div>
        <div className="flex justify-between text-xs text-slate-500 mb-1">
          <span>Stealth</span>
          <span>{stealth === 0 ? 'Noisy' : 'Slow & Low'}</span>
        </div>
        <input
          type="range" min="0" max="1" step="1" value={stealth}
          onChange={e => setStealth(Number(e.target.value))}
          className="w-full accent-indigo-500"
        />
      </div>
      <button
        onClick={handleRun}
        disabled={loading}
        className={`w-full py-2 rounded-lg text-sm font-medium transition-all
          ${ran ? 'bg-green-700 text-green-100' : 'bg-indigo-600 hover:bg-indigo-500 text-white'}
          ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
      >
        {loading ? 'Running...' : ran ? 'Fired!' : 'Run Simulation'}
      </button>
    </div>
  )
}

function AlertCard({ alert, selected, onClick }) {
  return (
    <div
      onClick={() => onClick(alert)}
      className={`p-4 border rounded-xl cursor-pointer transition-all
        ${selected
          ? 'bg-indigo-900/30 border-indigo-500/50'
          : 'bg-slate-800/40 border-slate-700/40 hover:border-slate-600/60 hover:bg-slate-800/60'
        }`}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full mt-0.5 flex-shrink-0 ${SEV_DOT[alert.severity]}`} />
          <p className="text-sm font-medium text-white leading-tight">{alert.name}</p>
        </div>
        <SeverityBadge severity={alert.severity} />
      </div>
      <div className="flex items-center gap-2 mb-2">
        <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${MITRE_COLORS[alert.mitre_id] || 'bg-slate-700 text-slate-300'}`}>
          {alert.mitre_id}
        </span>
        <span className="text-xs text-slate-500">{alert.matched_event_count} events</span>
      </div>
      <ConfidenceBar value={alert.confidence} />
      <p className="text-xs text-slate-500 mt-2">
        {new Date(alert.first_seen).toLocaleTimeString()}
      </p>
    </div>
  )
}

function TriageDrawer({ alert, onClose }) {
  const [detail, setDetail] = useState(null)
  const [runbook, setRunbook] = useState(null)
  const [loadingRunbook, setLoadingRunbook] = useState(false)
  const [runbookError, setRunbookError] = useState(null)

  useEffect(() => {
    if (!alert) return
    setDetail(null)
    setRunbook(null)
    setRunbookError(null)
    fetch(`${API}/alerts/${alert.id}`)
      .then(r => r.json())
      .then(setDetail)
      .catch(() => {})
  }, [alert])

  const generateRunbook = async () => {
    setLoadingRunbook(true)
    setRunbookError(null)
    try {
      const res = await fetch(`${API}/alerts/${alert.id}/runbook`, { method: 'POST' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail)
      setRunbook(data.content)
    } catch (e) {
      setRunbookError(e.message)
    } finally {
      setLoadingRunbook(false)
    }
  }

  const downloadRunbook = () => {
    const blob = new Blob([runbook], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `forgeguard-${alert.rule_id}-runbook.md`
    a.click()
  }

  if (!alert) return null

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-2xl bg-slate-900 border-l border-slate-700 flex flex-col h-full overflow-hidden">
        <div className="flex items-center justify-between p-5 border-b border-slate-700 flex-shrink-0">
          <div>
            <p className="text-xs text-slate-500 font-mono">{alert.rule_id}</p>
            <h2 className="text-base font-semibold text-white">{alert.name}</h2>
          </div>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <button onClick={onClose} className="text-slate-400 hover:text-white ml-2 text-xl leading-none">&times;</button>
          </div>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-5 scrollbar-thin">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-slate-800/60 rounded-lg p-3">
              <p className="text-xs text-slate-400 mb-1">MITRE Technique</p>
              <p className="text-sm font-mono text-indigo-300">{alert.mitre_id}</p>
              <p className="text-xs text-slate-400 mt-0.5">{alert.mitre_technique}</p>
            </div>
            <div className="bg-slate-800/60 rounded-lg p-3">
              <p className="text-xs text-slate-400 mb-1">Confidence</p>
              <ConfidenceBar value={alert.confidence} />
            </div>
          </div>

          {alert.affected_accounts?.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 mb-2">Affected Accounts</p>
              <div className="flex flex-wrap gap-1.5">
                {alert.affected_accounts.map(a => (
                  <span key={a} className="text-xs bg-slate-800 border border-slate-600 rounded px-2 py-0.5 font-mono text-slate-300">{a}</span>
                ))}
              </div>
            </div>
          )}

          {alert.affected_ips?.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 mb-2">Source IPs</p>
              <div className="flex flex-wrap gap-1.5">
                {alert.affected_ips.map(ip => (
                  <span key={ip} className="text-xs bg-red-900/30 border border-red-700/40 rounded px-2 py-0.5 font-mono text-red-300">{ip}</span>
                ))}
              </div>
            </div>
          )}

          {detail?.matched_events && (
            <div>
              <p className="text-xs text-slate-400 mb-2">Matched Events (sample)</p>
              <div className="bg-slate-950 rounded-lg p-3 max-h-48 overflow-y-auto scrollbar-thin">
                {detail.matched_events.map((e, i) => (
                  <pre key={i} className="text-xs text-green-300 font-mono leading-relaxed whitespace-pre-wrap break-all mb-2 last:mb-0">
                    {JSON.stringify(e, null, 2)}
                  </pre>
                ))}
              </div>
            </div>
          )}

          {alert.triage_steps && (
            <div>
              <p className="text-xs text-slate-400 mb-2">Quick Triage Steps</p>
              <ol className="space-y-1.5">
                {alert.triage_steps.map((step, i) => (
                  <li key={i} className="flex gap-2 text-xs text-slate-300">
                    <span className="text-indigo-400 font-mono flex-shrink-0">{i + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {!runbook && (
            <div>
              <button
                onClick={generateRunbook}
                disabled={loadingRunbook}
                className={`w-full py-2.5 rounded-lg text-sm font-medium transition-all
                  bg-indigo-600 hover:bg-indigo-500 text-white
                  ${loadingRunbook ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {loadingRunbook ? 'Generating AI Runbook...' : 'Generate AI Runbook'}
              </button>
              {runbookError && (
                <p className="text-xs text-red-400 mt-2">{runbookError}</p>
              )}
            </div>
          )}

          {runbook && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-slate-400">AI Runbook</p>
                <button
                  onClick={downloadRunbook}
                  className="text-xs text-indigo-400 hover:text-indigo-300 border border-indigo-700/50 rounded px-2 py-0.5"
                >
                  Download .md
                </button>
              </div>
              <div className="bg-slate-950 rounded-lg p-4 text-xs text-slate-300 leading-relaxed prose prose-invert prose-sm max-w-none">
                <ReactMarkdown>{runbook}</ReactMarkdown>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function App() {
  const [scenarios, setScenarios] = useState([])
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [toast, setToast] = useState(null)

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3000)
  }

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch(`${API}/alerts`)
      setAlerts(await res.json())
    } catch {}
  }, [])

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API}/stats`)
      setStats(await res.json())
    } catch {}
  }, [])

  useEffect(() => {
    fetch(`${API}/scenarios`).then(r => r.json()).then(setScenarios).catch(() => {})
    fetchAlerts()
    fetchStats()
    const interval = setInterval(() => { fetchAlerts(); fetchStats() }, 5000)
    return () => clearInterval(interval)
  }, [fetchAlerts, fetchStats])

  const handleRun = async (scenarioId, stealth) => {
    try {
      const res = await fetch(`${API}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId, stealth })
      })
      const data = await res.json()
      if (data.alerts?.length > 0) {
        showToast(`${data.alerts.length} alert(s) fired`)
      } else {
        showToast('No detections fired', 'info')
      }
      fetchAlerts()
      fetchStats()
    } catch (e) {
      showToast(e.message || 'Simulation failed', 'info')
    }
  }

  const handleReset = async () => {
    try {
      await fetch(`${API}/reset`, { method: 'DELETE' })
      setAlerts([])
      setStats(null)
      setSelectedAlert(null)
      fetchStats()
      showToast('Lab reset')
    } catch (e) {
      showToast(e.message || 'Reset failed', 'info')
    }
  }

  const coverage = stats ? Math.round((stats.techniques_fired?.length || 0) / 5 * 100) : 0

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-200">
      {toast && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-lg
          ${toast.type === 'success' ? 'bg-green-800 text-green-100' : 'bg-slate-700 text-slate-200'}`}>
          {toast.msg}
        </div>
      )}

      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white font-bold text-sm">FG</div>
          <div>
            <h1 className="text-base font-semibold text-white">ForgeGuard</h1>
            <p className="text-xs text-slate-500">Active Directory Blue Team Lab</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-xs text-slate-400">Live</span>
          </div>
          <button
            onClick={handleReset}
            className="text-xs text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 rounded-lg px-3 py-1.5 transition-colors"
          >
            Reset Lab
          </button>
        </div>
      </header>

      <div className="px-6 py-4 grid grid-cols-4 gap-3 border-b border-slate-800">
        <StatCard label="Total Alerts" value={stats?.total_alerts ?? 0} />
        <StatCard label="Critical" value={stats?.alerts_by_severity?.critical ?? 0} color="text-red-400" />
        <StatCard label="Techniques Fired" value={`${stats?.techniques_fired?.length ?? 0} / 5`} color="text-indigo-400" />
        <StatCard label="Runbooks Generated" value={stats?.runbooks_generated ?? 0} color="text-green-400" />
      </div>

      <div className="flex h-[calc(100vh-160px)]">
        <div className="w-80 border-r border-slate-800 flex flex-col">
          <div className="p-4 border-b border-slate-800">
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Detection Coverage</p>
            <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-indigo-500 rounded-full transition-all"
                style={{ width: `${coverage}%` }}
              />
            </div>
            <p className="text-xs text-slate-500 mt-1">{coverage}% of MITRE techniques detected this session</p>
          </div>
          <div className="p-4 border-b border-slate-800">
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">Attack Scenarios</p>
            <div className="space-y-2">
              {scenarios.map(s => (
                <ScenarioCard key={s.id} scenario={s} onRun={handleRun} />
              ))}
            </div>
          </div>
        </div>

        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-800 flex items-center justify-between">
            <p className="text-sm font-medium text-white">Alert Feed</p>
            <span className="text-xs text-slate-500">{alerts.length} alerts</span>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-thin">
            {alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-center">
                <p className="text-slate-500 text-sm">No alerts yet</p>
                <p className="text-slate-600 text-xs mt-1">Run a simulation to generate detections</p>
              </div>
            ) : (
              alerts.map(alert => (
                <AlertCard
                  key={alert.id}
                  alert={alert}
                  selected={selectedAlert?.id === alert.id}
                  onClick={setSelectedAlert}
                />
              ))
            )}
          </div>
        </div>
      </div>

      <TriageDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  )
}
