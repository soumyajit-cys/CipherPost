import { useEffect, useState } from 'react'
import { api } from '@/api'
import { Panel, LoadingState, ErrorState, EmptyState } from '@/components/ui/State'

interface Flow {
  id: string
  client: string
  server: string
  protocol: string
  port: number
  total_sessions: number
  encrypted_sessions: number
  plaintext_sessions: number
  encrypted_share: number | null
  best_version: string | null
  last_seen: string | null
}

export default function FlowsPage() {
  const [rows, setRows] = useState<Flow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [onlyPlain, setOnlyPlain] = useState(true)

  const load = async () => {
    try {
      const base = (import.meta as any).env?.VITE_API_BASE_URL ?? '/api/v1'
      const t = localStorage.getItem('cipherpost_token')
      const qs = onlyPlain ? '?unencrypted_within_days=30' : ''
      const res = await fetch(`${base}/flows${qs}`, {
        headers: t ? { Authorization: `Bearer ${t}` } : {},
      })
      if (!res.ok) throw new Error(`GET /flows → ${res.status}`)
      setRows((await res.json()) as Flow[])
    } catch (e) {
      setError(String(e))
    }
  }

  useEffect(() => { load() }, [onlyPlain])

  const exportCsv = async (id: string) => {
    const base = (import.meta as any).env?.VITE_API_BASE_URL ?? '/api/v1'
    const t = localStorage.getItem('cipherpost_token')
    const res = await fetch(`${base}/flows/${id}/history?days=30&format=csv`, {
      headers: t ? { Authorization: `Bearer ${t}` } : {},
    })
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `flow-${id}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  if (error) return <ErrorState message={error} onRetry={load} />
  if (!rows) return <LoadingState label="Loading mail flows…" />

  return (
    <Panel
      title="Mail flows"
      subtitle="Which flows sent mail unencrypted in the last 30 days? Encrypted share, best TLS, last seen."
    >
      <label className="mb-3 flex items-center gap-2 text-[12px] text-base-300">
        <input type="checkbox" checked={onlyPlain} onChange={(e) => setOnlyPlain(e.target.checked)} />
        Only flows with plaintext in the last 30 days
      </label>
      {rows.length === 0 ? (
        <EmptyState title="No flows" hint="No unencrypted mail in range — or no live data yet." />
      ) : (
        <ul className="divide-y divide-base-800">
          {rows.map((f) => (
            <li key={f.id} className="flex items-center justify-between gap-3 py-2 text-[12px]">
              <div className="min-w-0">
                <span className="font-mono font-semibold text-base-100">
                  {f.client} → {f.server}:{f.port}
                </span>
                <span className="ml-2 rounded bg-base-700 px-1.5 py-0.5 font-mono text-[10px] text-base-300">{f.protocol}</span>
                <div className="text-base-400">
                  {f.total_sessions} sessions · encrypted share {f.encrypted_share ?? 'n/a'} · best {f.best_version ?? 'none'} · last {f.last_seen ?? 'never'}
                </div>
              </div>
              <button
                className="shrink-0 rounded border border-base-600 px-2 py-1 text-[11px] text-base-300 hover:text-base-100"
                onClick={() => exportCsv(f.id)}
              >
                CSV
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
