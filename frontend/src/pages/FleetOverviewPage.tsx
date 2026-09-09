import { Link } from 'react-router-dom'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell, CartesianGrid } from 'recharts'
import { useFleetDrill } from '@/hooks/useApi'
import { ErrorState, EmptyState, LoadingState, Panel, Stat } from '@/components/ui/State'
import { SeverityBadge, CodeBlock } from '@/components/ui/primitives'
import { formatDateTime } from '@/lib/utils'
import { SEVERITY_ORDER, type SeverityLabel } from '@/api'

const SEV_COLORS: Record<SeverityLabel, string> = {
  critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#8b9cb5', none: '#64748b',
}

export default function FleetOverviewPage() {
  const { data, isLoading, isError, error, refetch } = useFleetDrill()

  if (isLoading) return <LoadingState label="Aggregating fleet…" />
  if (isError) return <ErrorState message={(error as Error)?.message} onRetry={() => refetch()} />
  if (!data || data.analyses.length === 0) {
    return (
      <EmptyState
        title="No completed analyses"
        hint="Upload a capture or start live capture to populate fleet statistics. Posture trends and severity distribution appear once sessions are analyzed."
        action={<Link to="/app/upload" className="rounded bg-accent px-3 py-1.5 text-sm font-semibold text-base-950 hover:bg-accent/90">Upload capture</Link>}
      />
    )
  }

  const sevData = Object.entries(data.overall.severityDistribution)
    .map(([k, v]) => ({ name: k, value: v as number }))
    .filter((d) => d.value > 0)
    .sort((a, b) => SEVERITY_ORDER[b.name as SeverityLabel] - SEVERITY_ORDER[a.name as SeverityLabel])

  const top = data.topFindingTypes.slice(0, 12)
  const maxTop = Math.max(...top.map((t) => t.count), 1)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold tracking-tight text-base-50">Fleet Overview</h1>
          <p className="max-w-[560px] text-[12px] leading-relaxed text-base-400">
            Aggregate posture across every analysis in this instance — trends animate as new sessions are scored. Color is reserved for severity only.
          </p>
        </div>
        <span className="rounded border border-base-600 bg-base-800 px-2 py-1 font-mono text-[11px] text-base-400">
          {data.analyses.length} analyses · {data.overall.totalSessions} sessions
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 rounded-md border border-base-600/60 bg-base-850 p-4 shadow-panel">
        <Stat label="Analyses" value={<span className="animate-tick">{data.analyses.length}</span>} />
        <Stat label="Total sessions" value={<span className="animate-tick">{data.overall.totalSessions}</span>} />
        <Stat label="Total findings" value={data.overall.totalFindings} valueClassName={data.overall.totalFindings ? 'text-sev-medium' : 'text-base-100'} />
        <Stat
          label="Avg posture"
          value={<span className="animate-tick tabular-nums">{data.overall.avgPosture}</span>}
          valueClassName={data.overall.totalFindings ? 'text-sev-medium' : 'text-positive'}
          hint="0–100, lower is healthier. Animates on change."
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Posture trend" subtitle="higher = more at-risk · updates live" className="xl:col-span-2">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={data.postureTrend} margin={{ left: -16, right: 8, top: 6 }}>
              <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" />
              <XAxis dataKey="date" tickFormatter={(d) => formatDateTime(d).split(',')[0]} tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#131a23', border: '1px solid #273442', borderRadius: 6, fontSize: 12 }}
                labelFormatter={(d) => formatDateTime(String(d))}
              />
              <Line type="monotone" dataKey="score" stroke="#f97316" strokeWidth={2} dot={{ r: 3, fill: '#f97316' }} activeDot={{ r: 5 }} isAnimationActive animationDuration={600} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Severity distribution" subtitle="across all findings">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={sevData} layout="vertical" margin={{ left: 16, right: 12 }}>
              <XAxis type="number" allowDecimals={false} tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={62} />
              <Tooltip cursor={{ fill: '#1a222d' }} contentStyle={{ background: '#131a23', border: '1px solid #273442', borderRadius: 6, fontSize: 12 }} formatter={(v: number) => [`${v}`, 'findings']} />
              <Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive animationDuration={600}>
                {sevData.map((d) => (
                  <Cell key={d.name} fill={SEV_COLORS[d.name as SeverityLabel] ?? '#64748b'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          {sevData.length === 0 && <p className="py-4 text-center text-sm text-base-400">No findings across the fleet.</p>}
        </Panel>
      </div>

      <Panel title="Top recurring finding types" subtitle="most frequent rule across sessions">
        {top.length === 0 ? (
          <EmptyState title="No recurring findings" hint="Once multiple sessions share the same rule, they appear ranked here." />
        ) : (
          <div className="space-y-2">
            {top.map((t) => (
              <div key={t.ruleId} className="flex items-center gap-3">
                <div className="w-8 shrink-0 text-right font-mono text-[11px] font-semibold tabular-nums text-base-300">{t.count}</div>
                <div className="w-48 shrink-0 truncate">
                  <CodeBlock className="text-[11px] text-accent">{t.ruleId}</CodeBlock>
                </div>
                <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-base-800" title={`${t.count} hits — ${t.ruleName}`}>
                  <div className="h-full rounded-full bg-sev-medium transition-all duration-700" style={{ width: `${(t.count / maxTop) * 100}%` }} />
                </div>
                <div className="hidden w-56 shrink-0 truncate text-[11px] text-base-400 sm:block">{t.ruleName}</div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Analyses" padded={false} className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-[12px]">
            <thead className="sticky top-0 bg-base-850">
              <tr className="border-b border-base-600/60">
                <th className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Analysis</th>
                <th className="hidden px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400 sm:table-cell">Date</th>
                <th className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Sessions</th>
                <th className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Findings</th>
                <th className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Max severity</th>
                <th className="px-3 py-2 text-right text-[11px] font-semibold uppercase tracking-wider text-base-400">Posture</th>
              </tr>
            </thead>
            <tbody>
              {data.analyses.map((a) => (
                <tr key={a.id} className="border-b border-base-700/50 transition-colors hover:bg-base-800/60">
                  <td className="px-3 py-2">
                    <Link to={`/app/analyses/${a.id}`} className="font-medium text-base-100 hover:text-accent">
                      {a.filename}
                    </Link>
                  </td>
                  <td className="hidden px-3 py-2 font-mono text-[11px] text-base-400 sm:table-cell">{formatDateTime(a.createdAt)}</td>
                  <td className="px-3 py-2 font-mono tabular-nums text-base-200">{a.sessionsCount}</td>
                  <td className="px-3 py-2 font-mono tabular-nums text-base-200">{a.findingsCount}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={a.maxSeverity} />
                  </td>
                  <td className="px-3 py-2 text-right">
                    <span className="font-mono text-[12px] font-bold tabular-nums text-base-100">{a.postureScore}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
