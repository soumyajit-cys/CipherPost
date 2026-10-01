import { useEffect, useState } from 'react'
import { Panel, LoadingState, ErrorState, EmptyState } from '@/components/ui/State'

interface RulePrecision {
  rule_id: string
  confirmed: number
  false_positive: number
  accepted_risk: number
  precision: number | null
  labels: number
}

export default function FeedbackPage() {
  const [rows, setRows] = useState<RulePrecision[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      const base = (import.meta as any).env?.VITE_API_BASE_URL ?? '/api/v1'
      const t = localStorage.getItem('cipherpost_token')
      const res = await fetch(`${base}/feedback/precision`, {
        headers: t ? { Authorization: `Bearer ${t}` } : {},
      })
      if (!res.ok) throw new Error(`GET /feedback/precision → ${res.status}`)
      setRows(((await res.json()) as { rules: RulePrecision[] }).rules)
    } catch (e) {
      setError(String(e))
    }
  }

  useEffect(() => { load() }, [])

  if (error) return <ErrorState message={error} onRetry={load} />
  if (!rows) return <LoadingState label="Loading label precision…" />

  return (
    <Panel
      title="Rule precision"
      subtitle="From analyst labels only (confirmed / false positive). Never used for automatic retraining."
    >
      {rows.length === 0 ? (
        <EmptyState title="No labels yet" hint="Label findings from any analysis to build per-rule precision." />
      ) : (
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left text-base-500">
              <th className="py-1 pr-3 font-mono">rule</th>
              <th className="py-1 pr-3">precision</th>
              <th className="py-1 pr-3">confirmed</th>
              <th className="py-1 pr-3">false&nbsp;positive</th>
              <th className="py-1">accepted&nbsp;risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-base-800">
            {rows.map((r) => (
              <tr key={r.rule_id}>
                <td className="py-1.5 pr-3 font-mono text-base-100">{r.rule_id}</td>
                <td className="py-1.5 pr-3 font-semibold text-base-100">
                  {r.precision === null ? 'n/a' : `${Math.round(r.precision * 100)}%`}
                </td>
                <td className="py-1.5 pr-3 text-positive">{r.confirmed}</td>
                <td className="py-1.5 pr-3 text-sev-critical">{r.false_positive}</td>
                <td className="py-1.5 text-sev-low">{r.accepted_risk}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  )
}
