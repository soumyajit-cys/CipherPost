import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAnalysisDetail } from '@/hooks/useApi'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { ErrorState, EmptyState, LoadingState, Panel, Stat } from '@/components/ui/State'
import { SeverityBadge, ScoreGauge, CodeBlock } from '@/components/ui/primitives'
import { formatBytes, formatDateTime, timeAgo } from '@/lib/utils'
import { SEVERITY_ORDER, type Finding, type SessionSummary } from '@/api'
import { api } from '@/api'
import { cn } from '@/lib/utils'

export default function AnalysisDetailPage() {
  const { id = '' } = useParams()
  const { data, isLoading, isError, error, refetch } = useAnalysisDetail(id)

  if (isLoading) return <LoadingState label="Loading analysis…" />
  if (isError) return <ErrorState message={(error as Error)?.message} onRetry={() => refetch()} />
  if (!data) return <ErrorState message="No data returned for this analysis." onRetry={() => refetch()} />

  const sevCounts = useMemo(() => {
    const counts: Partial<Record<string, number>> = {}
    for (const f of data.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1
    return counts
  }, [data.findings])

  return (
    <div>
      {/* Header */}
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4 border-b border-base-600/60 pb-4">
        <div className="min-w-0">
          <Link to="/" className="text-[11px] text-base-400 hover:text-accent">← All analyses</Link>
          <h1 className="truncate text-lg font-bold text-base-50">{data.filename}</h1>
          <p className="text-[12px] text-base-400">
            <CodeBlock className="text-[11px]">{data.id}</CodeBlock> · uploaded {formatDateTime(data.createdAt)}{' '}
            ({timeAgo(data.createdAt)}) · {formatBytes(data.fileSize)}
          </p>
        </div>
        <div className="flex items-center gap-6">
          <Stat label="Sessions" value={data.sessionsCount} />
          <Stat label="Findings" value={data.findingsCount} valueClassName={data.findingsCount ? 'text-sev-medium' : 'text-base-100'} />
          <Stat label="Anomalies" value={data.fleet.anomalyCount} valueClassName={data.fleet.anomalyCount ? 'text-sev-high' : 'text-base-100'} />
          <ScoreGauge score={data.postureScore} size="md" />
          <ExportButtons id={id} />
        </div>
      </div>

      {/* Severity strip */}
      <div className="mb-4 flex flex-wrap gap-1.5">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
          <span key={s} className="flex items-center gap-1.5 rounded border border-base-600/60 bg-base-850 px-2 py-1">
            <SeverityBadge severity={s} />
            <span className="cell-numeric text-[12px] text-base-300">{sevCounts[s] ?? 0}</span>
          </span>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Sessions */}
        <Panel
          title="Reconstructed sessions"
          subtitle={`${data.sessionsCount} total`}
          className="xl:col-span-1"
        >
          <SessionTable sessions={data.summaries} analysisId={id} />
        </Panel>

        {/* Findings */}
        <Panel
          title="Findings"
          subtitle={`${data.findings.length} prioritized by severity`}
          className="xl:col-span-1"
        >
          <FindingsList findings={data.findings} />
        </Panel>
      </div>
    </div>
  )
}

function ExportButtons({ id }: { id: string }) {
  const [copy, setCopy] = useState(false)
  const formats: Array<{ fmt: 'json' | 'html' | 'pdf'; label: string }> = [
    { fmt: 'json', label: 'JSON' },
    { fmt: 'html', label: 'HTML' },
    { fmt: 'pdf', label: 'PDF' },
  ]
  return (
    <div className="flex items-center gap-1.5">
      {formats.map(({ fmt, label }) => (
        <a
          key={fmt}
          href={api.reportUrl(id, fmt)}
          target="_blank"
          rel="noreferrer"
          className="rounded border border-base-600/70 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-base-300 hover:border-accent/60 hover:text-accent"
        >
          {label}
        </a>
      ))}
      <button
        onClick={() => { navigator.clipboard.writeText(id); setCopy(true); setTimeout(() => setCopy(false), 1500) }}
        className="rounded border border-base-600/70 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-base-300 hover:text-accent"
      >
        {copy ? '✓' : 'Copy id'}
      </button>
    </div>
  )
}

function SessionTable({ sessions, analysisId }: { sessions: SessionSummary[]; analysisId: string }) {
  const [protocol, setProtocol] = useState<string>('all')

  const rows = useMemo(
    () => (protocol === 'all' ? sessions : sessions.filter((s) => s.protocol === protocol)),
    [sessions, protocol],
  )
  const protocols = useMemo(() => [...new Set(sessions.map((s) => s.protocol))], [sessions])

  const columns: Column<SessionSummary>[] = [
    {
      key: 'fiveTuple',
      header: 'Connection',
      sortValue: (r) => r.fiveTuple,
      render: (r) => (
        <Link to={`/analyses/${analysisId}/sessions/${r.id}`} className="font-mono text-[11px] text-base-100 hover:text-accent" title={r.fiveTuple}>
          {r.fiveTuple}
        </Link>
      ),
      className: 'max-w-[240px]',
    },
    {
      key: 'protocol',
      header: 'Protocol',
      sortValue: (r) => r.protocol,
      render: (r) => <CodeBlock className="text-accent">{r.protocol}</CodeBlock>,
    },
    {
      key: 'tls',
      header: 'TLS',
      sortValue: (r) => r.tlsVersion ?? '',
      render: (r) => (
        <div>
          <CodeBlock className="text-base-200">{r.tlsVersion ?? '—'}</CodeBlock>
          <div className="text-[10px] text-base-400">{r.isStarttls ? 'STARTTLS' : 'implicit'}</div>
        </div>
      ),
    },
    {
      key: 'cipher',
      header: 'Cipher',
      sortValue: (r) => r.cipher ?? '',
      render: (r) => <CodeBlock className="text-[11px] text-base-200">{r.cipher ?? '—'}</CodeBlock>,
      className: 'max-w-[220px]',
    },
    {
      key: 'strength',
      header: 'Str',
      sortValue: (r) => r.cipherStrength ?? 0,
      numeric: true,
      render: (r) => <CipherStrength value={r.cipherStrength} />,
    },
    {
      key: 'pfs',
      header: 'PFS',
      sortValue: (r) => (r.pfsSupported == null ? null : r.pfsSupported),
      render: (r) => (
        <span className={r.pfsSupported == null ? 'text-base-400' : r.pfsSupported ? 'text-positive' : 'text-sev-high'}>
          {r.pfsSupported == null ? '—' : r.pfsSupported ? 'yes' : 'no'}
        </span>
      ),
    },
    {
      key: 'chain',
      header: 'Chain',
      sortValue: (r) => (r.certChainValid == null ? null : r.certChainValid),
      render: (r) =>
        r.certChainValid == null ? (
          <span className="text-base-400">—</span>
        ) : (
          <span className={r.certChainValid ? 'text-positive' : 'text-sev-high'}>
            {r.certChainValid ? 'valid' : 'bad'}
          </span>
        ),
    },
    {
      key: 'findingCount',
      header: 'Fnd',
      sortValue: (r) => r.findingCount,
      numeric: true,
      render: (r) => <span className="cell-numeric text-base-200">{r.findingCount}</span>,
    },
    {
      key: 'severity',
      header: 'Max sev',
      sortValue: (r) => SEVERITY_ORDER[r.maxSeverity],
      render: (r) => <SeverityBadge severity={r.maxSeverity} />,
    },
    {
      key: 'score',
      header: 'Score',
      sortValue: (r) => r.riskScore ?? -1,
      numeric: true,
      render: (r) => (
        <span className={cn('cell-numeric font-bold', r.riskScore != null && r.riskScore < 30 ? 'text-sev-low' : r.riskScore != null && r.riskScore < 60 ? 'text-sev-medium' : 'text-sev-high')}>
          {r.riskScore != null ? r.riskScore : '—'}
        </span>
      ),
    },
  ]

  return (
    <div>
      <div className="mb-2 flex items-center gap-1.5">
        <span className="text-[11px] uppercase tracking-wider text-base-400">Filter</span>
        <select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value)}
          className="rounded border border-base-600/60 bg-base-900 px-1.5 py-1 text-[12px] text-base-200"
        >
          <option value="all">all protocols</option>
          {protocols.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} dense />
    </div>
  )
}

function CipherStrength({ value }: { value: number | null }) {
  if (value == null) return <span className="text-base-400">—</span>
  const cls = value >= 0.85 ? 'text-positive' : value >= 0.6 ? 'text-sev-medium' : 'text-sev-high'
  return (
    <div className="flex items-center gap-1.5">
      <span className="h-1.5 w-10 overflow-hidden rounded-sm bg-base-800">
        <span className={cn('block h-full', value >= 0.85 ? 'bg-positive' : value >= 0.6 ? 'bg-sev-medium' : 'bg-sev-high')} style={{ width: `${value * 100}%` }} />
      </span>
      <span className={cn('cell-numeric font-mono text-[11px]', cls)}>{value.toFixed(2)}</span>
    </div>
  )
}

function FindingsList({ findings }: { findings: Finding[] }) {
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const rows = useMemo(() => {
    const list = severityFilter === 'all' ? findings : findings.filter((f) => f.severity === severityFilter)
    return [...list].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
  }, [findings, severityFilter])

  return (
    <div>
      <div className="mb-2 flex items-center gap-1.5">
        <span className="text-[11px] uppercase tracking-wider text-base-400">Severity</span>
        {['all', 'critical', 'high', 'medium', 'low', 'info'].map((s) => (
          <button
            key={s}
            onClick={() => setSeverityFilter(s)}
            className={cn(
              'rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase',
              severityFilter === s
                ? 'border-accent/60 bg-accent/10 text-accent'
                : 'border-base-600/60 text-base-400 hover:text-base-200',
            )}
          >
            {s}
          </button>
        ))}
      </div>

      {rows.length === 0 ? (
        <EmptyState title="No findings" hint="No rule triggered for this filter." />
      ) : (
        <ul className="scrollbar-thin max-h-[560px] divide-y divide-base-700/50 overflow-y-auto">
          {rows.map((f) => (
            <li key={f.id} className="py-2 first:pt-0 last:pb-0">
              <div className="flex items-start gap-2">
                <SeverityBadge severity={f.severity} className="mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-[13px] font-semibold text-base-100">{f.title}</span>
                    <CodeBlock className="shrink-0 text-[10px] text-base-400">{f.ruleId}</CodeBlock>
                  </div>
                  <p className="mt-0.5 text-[12px] leading-snug text-base-300">{f.description}</p>
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px]">
                    <span className="text-base-400">
                      session <CodeBlock className="text-[10px] text-base-300">{f.session.fiveTuple}</CodeBlock>
                    </span>
                    {f.reference && (
                      <span className="text-base-400">
                        ref <CodeBlock className="text-[10px] text-accent/90">{f.reference}</CodeBlock>
                      </span>
                    )}
                    {f.kind !== 'rule' && <span className="rounded bg-base-700 px-1 text-[10px] font-semibold uppercase text-base-200">{f.kind}</span>}
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}