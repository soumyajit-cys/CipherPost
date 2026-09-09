import { useEffect, useState } from 'react'
import { SeverityBadge } from '@/components/ui/primitives'

const SEED_ROWS = [
  { id: '0x1a', proto: 'SMTP', tuple: '192.168.12.4:48210 → 10.0.1.5:25', sev: 'critical', rule: 'RC4 cipher' },
  { id: '0x1b', proto: 'IMAP', tuple: '10.0.1.22:39102 → 10.0.1.5:993', sev: 'high', rule: 'TLS 1.0' },
  { id: '0x1c', proto: 'POP3', tuple: '192.168.12.9:50211 → 10.0.1.5:995', sev: 'medium', rule: 'SHA-1 cert' },
  { id: '0x1d', proto: 'SMTP', tuple: '10.0.1.8:41022 → 10.0.1.5:587', sev: 'low', rule: 'No PFS' },
]

export function HeroMock() {
  const [active, setActive] = useState(0)
  const [pulse, setPulse] = useState(false)

  useEffect(() => {
    const id = setInterval(() => {
      setActive((a) => (a + 1) % SEED_ROWS.length)
      setPulse(true)
      setTimeout(() => setPulse(false), 1200)
    }, 2200)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="overflow-hidden rounded-lg border border-base-600/60 bg-base-900 shadow-panel">
      {/* window chrome */}
      <div className="flex items-center justify-between border-b border-base-700/60 bg-base-850 px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-base-600" />
          <span className="h-2.5 w-2.5 rounded-full bg-base-600" />
          <span className="h-2.5 w-2.5 rounded-full bg-base-600" />
          <span className="ml-3 font-mono text-[11px] tracking-wide text-base-400">cipherpost — live capture: eth0 (SPAN) · eth0 promisc</span>
        </div>
        <span className="flex items-center gap-1.5 text-[11px] font-medium text-positive">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-positive" /> Streaming
        </span>
      </div>

      {/* toolbar */}
      <div className="flex items-center justify-between bg-base-900 px-3 py-2 text-[11px]">
        <span className="font-medium text-base-300">Sessions <span className="font-mono text-base-400">· 1,284 tracked</span></span>
        <span className="font-mono text-[11px] text-base-500">pkts 12.4k/s · dropped 0</span>
      </div>

      {/* table mock */}
      <div className="divide-y divide-base-800 border-y border-base-700/60 bg-base-950">
        {SEED_ROWS.map((r, i) => {
          const isActive = i === active
          return (
            <div
              key={r.id}
              className={`flex items-center gap-3 px-3 py-[9px] font-mono text-[12px] transition-colors ${isActive ? 'bg-accent/10' : ''} ${isActive && pulse ? 'animate-slide-in' : ''}`}
            >
              <span className="w-12 text-base-500">{r.id}</span>
              <span className="w-12 text-base-200">{r.proto}</span>
              <span className="flex-1 truncate text-base-300">{r.tuple}</span>
              <SeverityBadge severity={r.sev} className={`${isActive && pulse && r.sev === 'critical' ? 'animate-pulse-sev' : ''} shrink-0`} />
            </div>
          )
        })}
        {/* incoming row ghost */}
        <div className="flex items-center gap-3 px-3 py-[9px] font-mono text-[12px] opacity-60">
          <span className="w-12 text-base-500">0x1e</span>
          <span className="w-12 text-base-200">SMTP</span>
          <span className="flex-1 truncate text-base-300">192.168.12.4:48211 → 10.0.1.5:25</span>
          <span className="h-4 w-14 animate-pulse rounded bg-base-700" />
        </div>
      </div>

      {/* alert toast */}
      <div className="flex items-start gap-3 bg-sev-critical/10 px-3 py-2.5">
        <span className="mt-0.5 h-2 w-2 shrink-0 animate-pulse rounded-full bg-sev-critical" />
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-bold uppercase tracking-wide text-sev-critical">Critical · RC4 stream cipher negotiated</span>
            <span className="font-mono text-[11px] text-base-400">smtp_tls12_rc4 · 10.0.1.5:25</span>
          </div>
          <p className="font-mono text-[11px] leading-relaxed text-base-300">Session <span className="text-base-100">0x1a</span> negotiated <span className="text-sev-critical">RC4</span> (RFC 7465 prohibited). NIST SP 800-52r2 §3.3.1. <span className="text-accent">→ webhook dispatched 12ms ago</span></p>
        </div>
      </div>

      {/* footer stats */}
      <div className="flex gap-6 bg-base-850 px-3 py-2 text-[11px]">
        <span className="text-base-400">Posture <b className="font-mono text-sev-high">78/100</b></span>
        <span className="text-base-400">Findings <b className="font-mono text-base-100">3 critical · 7 high</b></span>
        <span className="ml-auto font-mono text-base-500">00:00:04 since last alert</span>
      </div>
    </div>
  )
}
