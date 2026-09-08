import { useMemo, useState } from 'react'
import { useSse } from '@/hooks/useSse'
import { API_MODE } from '@/api'
import { Panel, EmptyState } from '@/components/ui/State'
import { SeverityBadge } from '@/components/ui/primitives'
import { Link } from 'react-router-dom'

const BASE = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'

export default function LivePage() {
  const isLive = API_MODE === 'http'
  const { events, connected } = useSse(isLive ? `${BASE}/live/stream` : null, isLive)
  const [filter, setFilter] = useState<'all'|'sessions'|'findings'|'alerts'>('all')

  const filtered = useMemo(() => {
    if (filter==='all') return events
    return events.filter(e => e.event===filter || (e.data && e.data.event===filter))
  }, [events, filter])

  if (!isLive) {
    return (
      <div className="space-y-4">
        <h1 className="text-lg font-bold text-base-50">Live</h1>
        <Panel title="Live mode requires a running backend">
          <p className="text-sm text-base-400">The dashboard is in <code className="bg-base-800 px-1">mock</code> mode (fixture data). Start the stack with <code className="bg-base-800 px-1">VITE_API_MODE=http npm run dev</code> and ensure the capture worker is running on a SPAN/TAP interface.</p>
          <p className="mt-2 text-xs text-base-500">See README “Live capture deployment” and docs/design.md stage notes.</p>
        </Panel>
      </div>
    )
  }

  const sessions = events.filter(e=>e.event==='sessions')
  const findings = events.filter(e=>e.event==='findings')
  const alerts = events.filter(e=>e.event==='alerts')

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-bold text-base-50">Live feed <span className={`ml-2 inline-block h-2 w-2 rounded-full ${connected?'bg-positive animate-pulse':'bg-sev-medium'}`} /></h1>
        <div className="flex gap-1">
          {(['all','sessions','findings','alerts'] as const).map(f=>(
            <button key={f} onClick={()=>setFilter(f)} className={`rounded px-2 py-1 text-xs ${filter===f?'bg-accent text-white':'bg-base-800 text-base-400'}`}>{f}</button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-4">
        <Panel title="Sessions" subtitle={`${sessions.length} events`}><div className="text-2xl font-mono font-bold text-base-50">{sessions.length}</div></Panel>
        <Panel title="Findings" subtitle={`${findings.length} events`}><div className="text-2xl font-mono font-bold text-sev-medium">{findings.length}</div></Panel>
        <Panel title="Alerts" subtitle={`${alerts.length} dispatched`}><div className="text-2xl font-mono font-bold text-sev-high">{alerts.length}</div></Panel>
      </div>

      <Panel title={`Stream (${filtered.length})`} subtitle={connected ? 'connected via SSE' : 'disconnected - retrying'}>
        {filtered.length===0 ? <EmptyState title="Waiting for events" hint="Generate traffic: python scripts/traffic_generator.py  or  python scripts/replay_harness.py tests/fixtures" /> : (
          <div className="max-h-[60vh] overflow-auto divide-y divide-base-800">
            {filtered.slice(0,80).map((e,i)=>(
              <div key={i} className="py-2 flex items-center gap-3 text-xs">
                <span className="font-mono text-base-500">{new Date(e.ts||Date.now()).toLocaleTimeString()}</span>
                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${e.event==='alerts'?'bg-sev-high text-white': e.event==='findings'?'bg-sev-medium text-white':'bg-base-700 text-base-200'}`}>{e.event}</span>
                <span className="font-mono text-base-200 truncate">{JSON.stringify(e.data).slice(0,180)}</span>
                {e.data.severity && <SeverityBadge severity={e.data.severity} />}
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="PCAP import (replay/demo)" className="mt-4">
        <p className="text-xs text-base-400 mb-2">Import existing captures through the same live pipeline (for testing/demo). This feeds the capture worker in replay mode, so findings appear in the live feed above.</p>
        <Link to="/upload" className="inline-block rounded bg-accent px-3 py-1.5 text-sm font-medium text-white">Go to upload / replay</Link>
      </Panel>
    </div>
  )
}
