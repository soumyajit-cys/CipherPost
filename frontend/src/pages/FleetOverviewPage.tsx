import { Link } from 'react-router-dom'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell, CartesianGrid,
} from 'recharts'
import { useFleetDrill } from '@/hooks/useApi'
import { ErrorState, EmptyState, LoadingState, Panel, Stat } from '@/components/ui/State'
import { SeverityBadge, CodeBlock, scoreColorHex } from '@/components/ui/primitives'
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
    return <EmptyState title="No completed analyses" hint="Upload a capture to populate fleet statistics." />
  }

  const sevData = Object.entries(data.overall.severityDistribution)
    .map(([k, v]) => ({ name: k, value: v as number }))
    .filter((d) => d.value > 0)
    .sort((a, b) => SEVERITY_ORDER[b.name as SeverityLabel] - SEVERITY_ORDER[a.name as SeverityLabel])
  const maxSev = Math.max(...sevData.map((d) => d.value), 1)

  const top = data.topFindingTypes.slice(0, 12)
  const maxTop = Math.max(...top.map((t) => t.count), 1)

  return (
    <div>
      <div className="mb-4">
        <h1 className="text-lg font-bold text-base-50">Fleet Overview</h1>
        <p className="text-[12px] text-base-400">
          Aggregate cryptographic posture across every analysis in this instance.
        </p>
      </div>

      {/* KPI row */}
      <div className="mb-4 flex flex-wrap gap-6 rounded-md border border-base-600/60 bg-base-850 px-4 py-3">
        <Stat label="Analyses" value={data.analyses.length} />
        <Stat label="Total sessions" value={data.overall.totalSessions} />
        <Stat label="Total findings" value={data.overall.totalFindings} valueClassName={data.overall.totalFindings ? 'text-sev-medium' : 'text-base-100'} />
        <Stat label="Avg posture" value={data.overall.avgPosture} valueClassName={scoreColorHex(data.overall.avgPosture).replace('bg-', 'text-')} />
        <Stat label="Anomalous sessions" value={data.overall.anomalySessions} valueClassName={data.overall.anomalySessions ? 'text-sev-high' : 'text-base-100'} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Posture trend */}
        <Panel title="Posture score trend" subtitle="higher = more at-risk" className="xl:col-span-2">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={data.postureTrend} margin={{ left: -16, right: 8, top: 6 }}>
              <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" />
              <XAxis dataKey="date" tickFormatter={(d) => formatDateTime(d).split(',')[0]} tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#131a23', border: '1px solid #273442', borderRadius: 6, fontSize: 12 }}
                labelFormatter={(d) => formatDateTime(String(d))}
              />
              <Line
                type="monotone"
                dataKey="score"
                stroke="#f97316"
                strokeWidth={2}
                dot={{ r: 3, fill: '#f97316', fillOpacity: 0.9 }}
                activeDot={{ r: 5 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        {/* Severity distribution */}
        <Panel title="Severity distribution" subtitle="across all findings">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={sevData} layout="vertical" margin={{ left: 16, right: 12 }}>
              <XAxis type="number" allowDecimals={false} tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={62} />
              <Tooltip
                cursor={{ fill: '#1a222d' }}
                contentStyle={{ background: '#131a23', border: '1px solid #273442', borderRadius: 6, fontSize: 12 }}
                formatter={(v: number) => [`${v}`, 'findings']}
              />
              <Bar dataKey="value" radius={[0, 3, 3, 0]} label={{ position: 'right', fill: '#94a3b8', fontSize: 10 }}>
                {sevData.map((d) => (
                  <Cell key={d.name} fill={SEV_COLORS[d.name as SeverityLabel] ?? '#64748b'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          {sevData.length === 0 && <p className="py-4 text-center text-sm text-base-400">No findings across the fleet.</p>}
        </Panel>
      </div>

      {/* Top recurring finding types */}
      <Panel title="Top recurring finding types" subtitle="rule frequency across sessions" className="mt-4">
        {top.length === 0 ? (
          <EmptyState title="No recurring findings" />
        ) : (
          <div className="space-y-1.5">
            {top.map((t) => (
              <div key={t.ruleId} className="flex items-center gap-3">
                <div className="w-8 shrink-0 cell-numeric text-right font-mono text-[11px] text-base-300">{t.count}</div>
                <div className="w-48 shrink-0 truncate">
                  <CodeBlock className="text-[11px] text-base-200">{t.ruleId}</CodeBlock>
                </div>
                <div className="h-4 flex-1 overflow-hidden rounded-sm bg-base-800" title={t.ruleName}>
                  <div className="h-full bg-sev-medium/70" style={{ width: `${(t.count / maxTop) * 100}%` }} />
                </div>
                <div className="w-56 shrink-0 truncate text-[11px] text-base-400">{t.ruleName}</div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* Analysis table */}
      <Panel title="Analyses" className="mt-4" padded={false}>
        <div className="scrollbar-thin overflow-x-auto p-0">
        <table className="w-full border-collapse text-left text-[12px]">
          <thead>
            <tr className="border-b border-base-600/60">
              <th className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Analysis</th>
              <th className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Date</th>
              <th className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Sessions</th>
              <th className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Findings</th>
              <th className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Max severity</th>
              <th className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400">Posture</th>
            </tr>
          </thead>
          <tbody>
            {data.analyses.map((a) => (
              <tr key={a.id} className="border-b border-base-700/50 hover:bg-base-800">
                <td className="px-2 py-1.5">
                  <Link to={`/analyses/${a.id}`} className="text-base-100 hover:text-accent">{a.filename}</Link>
                </td>
                <td className="px-2 py-1.5 text-base-300">{formatDateTime(a.createdAt)}</td>
                <td className="px-2 py-1.5 cell-numeric text-base-200">{a.sessionsCount}</td>
                <td className="px-2 py-1.5 cell-numeric text-base-200">{a.findingsCount}</td>
                <td className="px-2 py-1.5"><SeverityBadge severity={a.maxSeverity} /></td>
                <td className="px-2 py-1.5 cell-numeric">
                  <span className={`font-bold ${a.postureScore < 30 ? 'text-sev-low' : a.postureScore < 60 ? 'text-sev-medium' : 'text-sev-high'}`}>
                    {a.postureScore}
                  </span>
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

// keep a reference so scoreColorHex usage stays consistent with primitives
export { scoreColorHex }