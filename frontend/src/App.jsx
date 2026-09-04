import React, { useState, useEffect, useCallback, useRef } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis } from 'recharts'

const API = '/api/v1'
const SEVERITY_COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#6b7280' }
const SCORE_COLOR = s => s < 40 ? '#16a34a' : s < 70 ? '#ca8a04' : '#dc2626'

function App() {
  const [view, setView] = useState('upload')
  const [jobs, setJobs] = useState([])
  const [activeJob, setActiveJob] = useState(null)

  const refreshJobs = useCallback(async () => {
    const res = await fetch(`${API}/jobs`)
    setJobs(await res.json())
  }, [])

  useEffect(() => { refreshJobs() }, [refreshJobs])

  const selectJob = id => { setActiveJob(id); setView('dashboard') }

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(180deg, #0f172a 0%, #1e293b 100%)' }}>
      <header style={{ padding: '1rem 2rem', borderBottom: '1px solid #334155', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#38bdf8' }}>
          CipherPost <span style={{ color: '#64748b', fontWeight: 400, fontSize: '0.85rem' }}>Crypto Posture Dashboard</span>
        </h1>
        <nav style={{ display: 'flex', gap: '0.5rem' }}>
          {[['upload', 'Upload'], ['jobs', 'Jobs'], ['dashboard', 'Dashboard']].map(([k, label]) => (
            <button key={k} onClick={() => { setView(k); if (k === 'jobs') refreshJobs() }}
              style={{ padding: '0.4rem 1rem', borderRadius: '6px', border: 'none', cursor: 'pointer',
                background: view === k ? '#38bdf8' : '#1e293b', color: view === k ? '#0f172a' : '#94a3b8',
                fontWeight: 600, fontSize: '0.82rem' }}>
              {label}
            </button>
          ))}
        </nav>
      </header>
      <main style={{ maxWidth: 1400, margin: '0 auto', padding: '1.5rem 2rem' }}>
        {view === 'upload' && <UploadView onUploaded={() => { refreshJobs(); setView('jobs') }} />}
        {view === 'jobs' && <JobsView jobs={jobs} onSelect={selectJob} onRefresh={refreshJobs} />}
        {view === 'dashboard' && activeJob && <DashboardView jobId={activeJob} />}
      </main>
    </div>
  )
}

function UploadView({ onUploaded }) {
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [msg, setMsg] = useState('')
  const inputRef = useRef()

  const upload = async () => {
    if (!file) return
    setUploading(true); setMsg('')
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await fetch(`${API}/upload`, { method: 'POST', body: fd })
      const data = await res.json()
      if (res.ok) { setMsg(`Job created: ${data.job_id}`); onUploaded() }
      else setMsg(data.detail || 'Upload failed')
    } catch (e) { setMsg('Network error') }
    setUploading(false)
  }

  return (
    <div style={{ textAlign: 'center', padding: '4rem 0' }}>
      <div style={{ background: '#1e293b', borderRadius: '12px', padding: '3rem', maxWidth: 520, margin: '0 auto', border: '1px solid #334155' }}>
        <h2 style={{ fontSize: '1.2rem', color: '#f1f5f9', marginBottom: '1rem' }}>Upload PCAP for Analysis</h2>
        <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          Supports SMTP, IMAP, POP3 captures with or without TLS/STARTTLS
        </p>
        <div style={{ border: '2px dashed #475569', borderRadius: '8px', padding: '2rem', cursor: 'pointer', marginBottom: '1rem' }}
          onClick={() => inputRef.current?.click()}>
          <input ref={inputRef} type="file" accept=".pcap,.pcapng" hidden onChange={e => setFile(e.target.files[0])} />
          <p style={{ color: file ? '#38bdf8' : '#64748b', fontSize: '0.9rem' }}>
            {file ? file.name : 'Click to select .pcap file'}
          </p>
          {file && <p style={{ color: '#64748b', fontSize: '0.78rem', marginTop: '0.3rem' }}>{(file.size / 1024 / 1024).toFixed(1)} MB</p>}
        </div>
        <button onClick={upload} disabled={!file || uploading}
          style={{ padding: '0.6rem 2rem', borderRadius: '8px', border: 'none', cursor: file && !uploading ? 'pointer' : 'default',
            background: file && !uploading ? '#38bdf8' : '#334155', color: file ? '#0f172a' : '#64748b',
            fontWeight: 600, fontSize: '0.9rem' }}>
          {uploading ? 'Analyzing...' : 'Upload & Analyze'}
        </button>
        {msg && <p style={{ marginTop: '1rem', color: '#38bdf8', fontSize: '0.85rem' }}>{msg}</p>}
      </div>
    </div>
  )
}

function JobsView({ jobs, onSelect, onRefresh }) {
  const statusColor = { pending: '#ca8a04', processing: '#38bdf8', completed: '#16a34a', failed: '#dc2626' }
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2 style={{ fontSize: '1.1rem', color: '#f1f5f9' }}>Analysis Jobs</h2>
        <button onClick={onRefresh} style={{ padding: '0.3rem 0.8rem', borderRadius: '6px', border: '1px solid #475569', background: '#1e293b', color: '#94a3b8', cursor: 'pointer', fontSize: '0.8rem' }}>Refresh</button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {jobs.length === 0 && <p style={{ color: '#64748b' }}>No jobs yet. Upload a PCAP to get started.</p>}
        {jobs.map(j => (
          <div key={j.id} onClick={() => onSelect(j.id)}
            style={{ background: '#1e293b', borderRadius: '8px', padding: '0.8rem 1.2rem', cursor: 'pointer',
              border: '1px solid #334155', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <span style={{ fontWeight: 600, color: '#e2e8f0', fontSize: '0.9rem' }}>{j.filename}</span>
              <span style={{ marginLeft: '0.8rem', color: '#64748b', fontSize: '0.78rem' }}>
                {(j.file_size / 1024 / 1024).toFixed(1)} MB | {j.created_at ? new Date(j.created_at).toLocaleString() : '—'}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {j.status === 'processing' && <div style={{ width: 60, height: 4, background: '#334155', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${j.progress * 100}%`, height: '100%', background: '#38bdf8', borderRadius: 2 }} />
              </div>}
              <span style={{ padding: '0.2rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600,
                background: `${statusColor[j.status]}20`, color: statusColor[j.status] }}>
                {j.status}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function DashboardView({ jobId }) {
  const [job, setJob] = useState(null)
  const [sessions, setSessions] = useState([])
  const [findings, setFindings] = useState([])
  const [fleet, setFleet] = useState(null)
  const [shap, setShap] = useState([])
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    const load = async () => {
      const [j, s, f, fl, sp] = await Promise.all([
        fetch(`${API}/jobs/${jobId}`).then(r => r.json()),
        fetch(`${API}/jobs/${jobId}/sessions`).then(r => r.json()),
        fetch(`${API}/jobs/${jobId}/findings`).then(r => r.json()),
        fetch(`${API}/jobs/${jobId}/fleet`).then(r => r.json()),
        fetch(`${API}/jobs/${jobId}/shap`).then(r => r.json()),
      ])
      setJob(j); setSessions(s); setFindings(f); setFleet(fl); setShap(sp)
    }
    load()
  }, [jobId])

  if (!job) return <p style={{ color: '#64748b' }}>Loading...</p>

  const severityData = fleet?.severity_distribution ? Object.entries(fleet.severity_distribution).map(([k, v]) => ({ name: k, value: v })) : []
  const protocolData = Object.entries(sessions.reduce((acc, s) => { acc[s.protocol] = (acc[s.protocol] || 0) + 1; return acc }, {})).map(([k, v]) => ({ name: k, count: v }))
  const scoreData = sessions.map(s => ({ name: s.five_tuple?.slice(0, 30), score: s.risk_score || 0, anomaly: s.is_anomaly }))

  const tabs = [['overview', 'Overview'], ['findings', 'Findings'], ['sessions', 'Sessions'], ['shap', 'SHAP']]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', color: '#f1f5f9' }}>{job.filename}</h2>
          <p style={{ color: '#64748b', fontSize: '0.8rem' }}>{job.id} | {job.status} | {job.message}</p>
        </div>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          {['json', 'html', 'pdf'].map(fmt => (
            <a key={fmt} href={`${API}/jobs/${jobId}/report.${fmt}`} target="_blank" rel="noreferrer"
              style={{ padding: '0.3rem 0.7rem', borderRadius: '6px', border: '1px solid #475569', background: '#1e293b',
                color: '#38bdf8', textDecoration: 'none', fontSize: '0.78rem', fontWeight: 600 }}>
              {fmt.toUpperCase()}
            </a>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '1.2rem' }}>
        {tabs.map(([k, label]) => (
          <button key={k} onClick={() => setActiveTab(k)}
            style={{ padding: '0.35rem 0.8rem', borderRadius: '6px', border: 'none', cursor: 'pointer',
              background: activeTab === k ? '#38bdf8' : '#1e293b', color: activeTab === k ? '#0f172a' : '#94a3b8',
              fontWeight: 600, fontSize: '0.8rem' }}>
            {label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
          <StatCard label="Sessions" value={fleet?.total_sessions || 0} />
          <StatCard label="Fleet Score" value={`${fleet?.fleet_score || 0}/100`} color={SCORE_COLOR(fleet?.fleet_score || 0)} />
          <StatCard label="Findings" value={findings.length} color={findings.length > 0 ? '#ca8a04' : '#16a34a'} />
          <StatCard label="Anomalies" value={fleet?.anomaly_count || 0} color={fleet?.anomaly_count > 0 ? '#ea580c' : '#16a34a'} />
          {severityData.length > 0 && <div style={{ gridColumn: 'span 2', background: '#1e293b', borderRadius: '8px', padding: '1rem', border: '1px solid #334155' }}>
            <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginBottom: '0.5rem' }}>Severity Distribution</p>
            <ResponsiveContainer width="100%" height={160}>
              <PieChart><Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} label>
                {severityData.map(e => <Cell key={e.name} fill={SEVERITY_COLORS[e.name] || '#64748b'} />)}
              </Pie><Tooltip /></PieChart>
            </ResponsiveContainer>
          </div>}
          {scoreData.length > 0 && <div style={{ gridColumn: 'span 2', background: '#1e293b', borderRadius: '8px', padding: '1rem', border: '1px solid #334155' }}>
            <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginBottom: '0.5rem' }}>Posture Scores by Session</p>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={scoreData}><XAxis dataKey="name" hide /><YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 10 }} />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {scoreData.map(e => <Cell key={e.name} fill={SCORE_COLOR(e.score)} />)}
                </Bar><Tooltip />
              </BarChart>
            </ResponsiveContainer>
          </div>}
        </div>
      )}

      {activeTab === 'findings' && (
        <div style={{ background: '#1e293b', borderRadius: '8px', padding: '1rem', border: '1px solid #334155' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #334155', textAlign: 'left' }}>
                {['Severity', 'Rule', 'Title', 'Description'].map(h => <th key={h} style={{ padding: '0.5rem', color: '#94a3b8', fontWeight: 600 }}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '0.4rem 0.5rem' }}>
                    <span style={{ padding: '0.15rem 0.4rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 700,
                      background: `${SEVERITY_COLORS[f.severity]}20`, color: SEVERITY_COLORS[f.severity] }}>
                      {f.severity}
                    </span>
                  </td>
                  <td style={{ padding: '0.4rem 0.5rem', color: '#64748b', fontFamily: 'monospace', fontSize: '0.78rem' }}>{f.rule_id}</td>
                  <td style={{ padding: '0.4rem 0.5rem', color: '#e2e8f0', fontWeight: 500 }}>{f.title}</td>
                  <td style={{ padding: '0.4rem 0.5rem', color: '#94a3b8', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.description}
                  </td>
                </tr>
              ))}
              {findings.length === 0 && <tr><td colSpan={4} style={{ padding: '1rem', color: '#64748b', textAlign: 'center' }}>No findings</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'sessions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {sessions.map(s => (
            <div key={s.id} style={{ background: '#1e293b', borderRadius: '8px', padding: '0.7rem 1rem', border: '1px solid #334155',
              display: 'grid', gridTemplateColumns: '80px 1fr 100px 100px 80px 70px', gap: '0.8rem', alignItems: 'center', fontSize: '0.82rem' }}>
              <span style={{ fontWeight: 600, color: '#38bdf8' }}>{s.protocol}</span>
              <span style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: '0.78rem', overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.five_tuple}</span>
              <span style={{ color: '#e2e8f0' }}>{s.tls_version || '—'}</span>
              <span style={{ color: '#e2e8f0', fontSize: '0.78rem' }}>{s.negotiated_cipher || '—'}</span>
              <span style={{ color: SCORE_COLOR(s.risk_score || 0), fontWeight: 700 }}>{s.risk_score || 0}/100</span>
              <span>{s.is_anomaly ? <span style={{ color: '#ea580c' }}>⚠</span> : '—'}</span>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'shap' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '1rem' }}>
          {Object.entries(shap.reduce((acc, r) => { (acc[r.session_id] = acc[r.session_id] || []).push(r); return acc }, {}))
            .map(([sid, rows]) => (
              <div key={sid} style={{ background: '#1e293b', borderRadius: '8px', padding: '1rem', border: '1px solid #334155' }}>
                <p style={{ fontSize: '0.78rem', color: '#38bdf8', marginBottom: '0.5rem', fontFamily: 'monospace' }}>{sid.slice(0, 40)}</p>
                <ResponsiveContainer width="100%" height={Math.min(rows.length * 22 + 20, 200)}>
                  <BarChart data={rows.slice(0, 8).map(r => ({ feature: r.feature?.slice(0, 20), impact: r.impact }))} layout="vertical" margin={{ left: 100 }}>
                    <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} />
                    <YAxis type="category" dataKey="feature" tick={{ fill: '#94a3b8', fontSize: 10 }} width={100} />
                    <Bar dataKey="impact" radius={[0, 4, 4, 0]}>
                      {rows.slice(0, 8).map((r, i) => <Cell key={i} fill={r.impact > 0 ? '#dc2626' : '#16a34a'} />)}
                    </Bar>
                    <Tooltip />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ))}
          {shap.length === 0 && <p style={{ color: '#64748b' }}>No SHAP data available</p>}
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: '#1e293b', borderRadius: '8px', padding: '1rem', border: '1px solid #334155' }}>
      <p style={{ fontSize: '0.78rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</p>
      <p style={{ fontSize: '1.5rem', fontWeight: 700, color: color || '#f1f5f9', marginTop: '0.3rem' }}>{value}</p>
    </div>
  )
}

export default App
