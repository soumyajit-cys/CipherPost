import { useEffect, useState } from 'react'
import { api } from '@/api'
import type { Suppression } from '@/api'
import { Panel, LoadingState, ErrorState, EmptyState } from '@/components/ui/State'
import { cn } from '@/lib/utils'

export default function SuppressionsPage() {
  const [rows, setRows] = useState<Suppression[] | null>(null)
  const [expiring, setExpiring] = useState<Suppression[]>([])
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      const [all, soon] = await Promise.all([
        api.listSuppressions?.() ?? Promise.resolve([]),
        api.suppressionsExpiring?.() ?? Promise.resolve([]),
      ])
      setRows(all as Suppression[])
      setExpiring(soon as Suppression[])
    } catch (e) {
      setError(String(e))
    }
  }

  useEffect(() => { load() }, [])

  if (error) return <ErrorState message={`Suppressions unavailable: ${error}`} />
  if (!rows) return <LoadingState label="Loading suppressions…" />

  const active = rows.filter((s) => s.active)
  const expired = rows.filter((s) => !s.active && s.status === 'approved')

  return (
    <div className="space-y-4">
      <Panel title="Suppressions" subtitle="Accepted-risk exceptions: stored findings stay visible, alerts and tickets skip them">
        {expiring.length > 0 && (
          <div className="mb-3 rounded border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-[12px] text-sev-medium">
            {expiring.length} suppression(s) expire within 14 days — renew or let them lapse back into alerting.
          </div>
        )}
        <h3 className="mb-2 text-[12px] font-bold uppercase tracking-wide text-base-400">Active ({active.length})</h3>
        {active.length === 0 ? <EmptyState title="No active suppressions" hint="Use Suppress on a finding to request one." /> : (
          <ul className="divide-y divide-base-800">
            {active.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 py-2 text-[12px]">
                <div className="min-w-0">
                  <span className="font-mono font-semibold text-base-100">{s.rule_id}</span>
                  <span className={cn('ml-2 rounded px-1.5 py-0.5 text-[10px]', s.status === 'approved' ? 'bg-positive/15 text-positive' : 'bg-sev-medium/15 text-sev-medium')}>{s.status}</span>
                  <div className="truncate text-base-400">{s.reason} · by {s.created_by} · expires {s.expires_at}</div>
                </div>
                <ApproveButtons id={s.id} status={s.status} reload={load} />
              </li>
            ))}
          </ul>
        )}
        <h3 className="mb-2 mt-4 text-[12px] font-bold uppercase tracking-wide text-base-400">Expired ({expired.length})</h3>
        {expired.length === 0 ? <p className="text-[12px] text-base-500">None.</p> : (
          <ul className="divide-y divide-base-800">
            {expired.map((s) => (
              <li key={s.id} className="py-2 text-[12px] text-base-400">
                <span className="font-mono">{s.rule_id}</span> — {s.reason} (expired {s.expires_at})
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )

  function ApproveButtons({ id, status, reload }: { id: number; status: string; reload: () => void }) {
    if (status === 'approved') return null
    return (
      <div className="flex shrink-0 gap-1.5">
        <button className="rounded bg-positive/20 px-2 py-1 text-[11px] text-positive" onClick={async () => { await api.updateSuppression?.(id, { status: 'approved' }); reload() }}>Approve</button>
        <button className="rounded bg-sev-critical/15 px-2 py-1 text-[11px] text-sev-critical" onClick={async () => { await api.updateSuppression?.(id, { status: 'rejected' }); reload() }}>Reject</button>
      </div>
    )
  }
}
