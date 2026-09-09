import { useEffect, useMemo, useRef, useState } from 'react'
import { useSse } from '@/hooks/useSse'
import { API_MODE } from '@/api'
import { Panel, EmptyState, Stat } from '@/components/ui/State'
import { SeverityBadge } from '@/components/ui/primitives'
import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'

const BASE = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'

export default function LivePage() {
  const isLive = API_MODE === 'http'
  const { events, connected } = useSse(isLive ? `${BASE}/live/stream` : null, isLive)
  const [filter, setFilter] = useState<'all' | 'sessions' | 'findings' | 'alerts'>('all')
  const [newIds, setNewIds] = useState<Set<string>>(new Set())
  const prevLen = useRef(0)

  useEffect(() => {
    if (events.length > prevLen.current) {
      const added = events.slice(0, events.length - prevLen.current)
      const ids = new Set(added.map((e, i) => `${e.event}-${e.ts}-${i}`))
      setNewIds(ids)
      const t = setTimeout(() => setNewIds(new Set()), 900)
      return () => clearTimeout(t)
    }
    prevLen.current = events.length
  }, [events.length, events])

  const filtered = useMemo(() => {
    if (filter === 'all') return events
    return events.filter((e) => e.event === filter || (e.data && e.data.event === filter))
  }, [events, filter])

  if (!isLive) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-bold text-base-50">Live</h1>
          <span className="rounded border border-sev-medium/30 bg-sev-medium/10 px-2 py-0.5 text-[11px] font-medium text-sev-medium">fixture mode</span>
        </div>
        <Panel title="Live mode requires a running backend">
          <div className="space-y-3">
            <p className="text-sm leading-relaxed text-base-300">
              The dashboard is in <code className="rounded bg-base-800 px-1 py-0.5 font-mono text-xs text-accent">mock</code> mode — showing fixture data. The live sensor is a separate, always-on service.
            </p>
            <div className="rounded border border-base-700/60 bg-base-950 p-3 font-mono text-xs leading-relaxed text-base-400">
              <div className="text-base-300"># start the stack</div>
              docker compose -f docker/docker-compose.yml up --build
              <br />
              <span className="text-base-500"># or locally</span> VITE_API_MODE=http npm run dev
            </div>
            <p className="text-xs text-base-500">See README “Live capture deployment” — SPAN/TAP, <code className="font-mono text-[11px]">CAP_NET_RAW</code>, rolling retention, and replay demo.</p>
            <Link to="/app" className="inline-flex rounded bg-base-800 px-3 py-1.5 text-sm font-medium text-base-200 hover:bg-base-700">
              Browse analyses →
            </Link>
          </div>
        </Panel>
      </div>
    )
  }

  const sessions = events.filter((e) => e.event === 'sessions')
  const findings = events.filter((e) => e.event === 'findings')
  const alerts = events.filter((e) => e.event === 'alerts')

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-bold tracking-tight text-base-50">Live</h1>
          <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide', connected ? 'border-positive/30 bg-positive/10 text-positive' : 'border-sev-critical/30 bg-sev-critical/10 text-sev-critical')}>
            <span className={cn('h-1.5 w-1.5 rounded-full', connected ? 'bg-positive animate-pulse' : 'bg-sev-critical')} />
            {connected ? 'Streaming' : 'Reconnecting'}
          </span>
          <span className="hidden font-mono text-xs text-base-500 sm:inline">cipherpost:live:stream · SSE</span>
        </div>
        <div className="flex items-center gap-1 rounded bg-base-900 p-1">
          {(['all', 'sessions', 'findings', 'alerts'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn('rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors', filter === f ? 'bg-accent text-base-950' : 'text-base-400 hover:bg-base-800 hover:text-base-200')}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Panel padded={false} className="overflow-hidden">
          <div className="p-3">
            <Stat label="Sessions" value={<span className="animate-tick tabular-nums">{sessions.length}</span>} hint="Reassembled 5-tuples" />
            <div className="mt-2 text-xs text-base-500">Real-time reassembly · bounded memory</div>
          </div>
          <div className="h-1 w-full bg-base-800">
            <div className="h-full bg-accent transition-all duration-700" style={{ width: `${Math.min(100, sessions.length * 4)}%` }} />
          </div>
        </Panel>
        <Panel padded={false} className="overflow-hidden">
          <div className="p-3">
            <Stat label="Findings" value={<span className={cn('tabular-nums', findings.length && 'text-sev-medium')}>{findings.length}</span>} valueClassName={findings.length ? 'text-sev-medium' : undefined} />
            <div className="mt-2 text-xs text-base-500">Severity-ranked, threshold + dedup</div>
          </div>
          <div className="h-1 w-full bg-base-800">
            <div className="h-full bg-sev-medium transition-all duration-700" style={{ width: `${Math.min(100, findings.length * 6)}%` }} />
          </div>
        </Panel>
        <Panel padded={false} className="overflow-hidden">
          <div className="p-3">
            <Stat label="Alerts dispatched" value={<span className={cn('tabular-nums', alerts.length && 'text-sev-critical')}>{alerts.length}</span>} valueClassName={alerts.length ? 'text-sev-critical' : undefined} />
            <div className="mt-2 text-xs text-base-500">webhook / Slack / SIEM · rate-limited</div>
          </div>
          <div className="h-1 w-full bg-base-800">
            <div className="h-full bg-sev-critical transition-all duration-700" style={{ width: `${Math.min(100, alerts.length * 8)}%` }} />
          </div>
        </Panel>
      </div>

      <Panel
        title={`Stream`}
        subtitle={`${filtered.length} events · ${connected ? 'connected via SSE — new rows slide in' : 'disconnected — retrying with backoff'}`}
        actions={
          <span className="font-mono text-[11px] text-base-500">
            {new Date().toLocaleTimeString()} · {filtered.length} total
          </span>
        }
        padded={false}
      >
        {filtered.length === 0 ? (
          <EmptyState
            title="Waiting for events"
            hint="Generate traffic to see the pipeline live: python scripts/traffic_generator.py  — or replay fixtures: python scripts/replay_harness.py tests/fixtures --mode capture"
            action={<Link to="/app/upload" className="rounded bg-accent px-3 py-1.5 text-sm font-semibold text-base-950 hover:bg-accent/90">Replay a PCAP</Link>}
          />
        ) : (
          <div className="max-h-[62vh] overflow-auto divide-y divide-base-800/60">
            {filtered.slice(0, 80).map((e, i) => {
              const key = `${e.event}-${e.ts}-${i}`
              const isNew = newIds.has(key)
              const sev = (e.data && (e.data.severity || e.data.max_severity)) || null
              return (
                <div
                  key={key}
                  className={cn('flex items-center gap-3 px-3 py-2 text-xs transition-colors', isNew && 'animate-slide-in bg-accent/5', sev === 'critical' && isNew && 'bg-sev-critical/5')}
                >
                  <span className="w-20 shrink-0 font-mono text-[11px] tabular-nums text-base-500">{new Date(e.ts || Date.now()).toLocaleTimeString()}</span>
                  <span className={cn('shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide', e.event === 'alerts' ? 'bg-sev-critical text-white' : e.event === 'findings' ? 'bg-sev-medium text-white' : 'bg-base-700 text-base-200')}>
                    {e.event}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-base-200">{JSON.stringify(e.data).slice(0, 200)}</span>
                  {sev && <SeverityBadge severity={sev} className={cn(sev === 'critical' && isNew && 'animate-pulse-sev')} />}
                </div>
              )
            })}
          </div>
        )}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="PCAP import (same pipeline)" subtitle="forensic replay · demo mode">
          <p className="text-xs leading-relaxed text-base-400">
            Import archived captures through the identical live pipeline — no separate code path. Useful for testing, demos, and replaying incidents where live network access isn’t available.
          </p>
          <Link to="/app/upload" className="mt-3 inline-flex rounded bg-accent px-3 py-1.5 text-sm font-semibold text-base-950 hover:bg-accent/90">
            Go to upload / replay →
          </Link>
        </Panel>
        <Panel title="Alert channels" subtitle="pluggable dispatcher">
          <p className="text-xs leading-relaxed text-base-400">
            Webhook is the base; Slack and SIEM (syslog/CEF) are adapters. Configure threshold, dedup window, and rate limit — then watch alerts slide in above.
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[11px]">
            <span className="rounded border border-base-600 bg-base-800 px-2 py-1 text-base-300">webhook</span>
            <span className="rounded border border-base-600 bg-base-800 px-2 py-1 text-base-300">slack</span>
            <span className="rounded border border-base-600 bg-base-800 px-2 py-1 text-base-300">syslog CEF</span>
            <span className="rounded border border-base-600 bg-base-800 px-2 py-1 text-base-300">email</span>
          </div>
        </Panel>
      </div>
    </div>
  )
}
