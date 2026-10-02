import { useEffect, useState } from 'react'
import { Panel, LoadingState, ErrorState, EmptyState } from '@/components/ui/State'
import { CodeBlock } from '@/components/ui/primitives'

interface QualityRow {
  rule_id: string
  findings: number
  alerts: number
  confirmed: number
  false_positive: number
  accepted_risk: number
  suppressed: number
  precision: number | null
  tta_hours_median: number | null
  needs_review: boolean
}

export default function QualityPage() {
  const [rows, setRows] = useState<QualityRow[] | null>(null)
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      const base = (import.meta as any).env?.VITE_API_BASE_URL ?? '/api/v1'
      const t = localStorage.getItem('cipherpost_token')
      const res = await fetch(`${base}/alerts/quality`, {
        headers: t ? { Authorization: `Bearer ${t}` } : {},
      })
      if (!res.ok) throw new Error(`GET /alerts/quality → ${res.status}`)
      const body = (await res.json()) as { rules: QualityRow[]; note: string }
      setRows(body.rules)
      setNote(body.note)
    } catch (e) {
      setError(String(e))
    }
  }

  useEffect(() => { load() }, [])

  if (error) return <ErrorState message={error} onRetry={load} />
  if (!rows) return <LoadingState label="Computing alert quality…" />

  return (
    <Panel
      title="Alert quality"
      subtitle="Measured per-rule precision, volume, and acknowledgement time. Precision is null without analyst labels — never guessed."
    >
      <p className="mb-3 text-[11px] text-base-500">{note}</p>
      {rows.length === 0 ? (
        <EmptyState title="No data" hint="Quality appears once findings and alerts exist." />
      ) : (
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left text-base-500">
              <th className="py-1 pr-3 font-mono">rule</th>
              <th className="py-1 pr-3">precision</th>
              <th className="py-1 pr-3">alerts</th>
              <th className="py-1 pr-3">findings</th>
              <th className="py-1 pr-3">TTA med (h)</th>
              <th className="py-1">flags</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-base-800">
            {rows.map((r) => (
              <tr key={r.rule_id}>
                <td className="py-1.5 pr-3"><CodeBlock className="text-[11px]">{r.rule_id}</CodeBlock></td>
                <td className="py-1.5 pr-3 font-mono">{r.precision === null ? 'n/a' : `${Math.round(r.precision * 100)}%`}</td>
                <td className="py-1.5 pr-3 font-mono tabular-nums">{r.alerts}</td>
                <td className="py-1.5 pr-3 font-mono tabular-nums">{r.findings}</td>
                <td className="py-1.5 pr-3 font-mono">{r.tta_hours_median ?? '—'}</td>
                <td className="py-1.5">
                  {r.needs_review && (
                    <span className="rounded bg-sev-medium/15 px-1.5 py-0.5 text-[10px] text-sev-medium">
                      needs labels
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  )
}
