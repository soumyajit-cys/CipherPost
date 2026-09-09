import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAnalysisDetail, useSessionDetail } from '@/hooks/useApi'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { ErrorState, EmptyState, LoadingState, Panel, Stat } from '@/components/ui/State'
import { SeverityBadge, ScoreGauge, CodeBlock } from '@/components/ui/primitives'
import { CertChainViewer } from '@/components/ui/CertChainViewer'
import { ExplanationPanel } from '@/components/ui/ExplanationPanel'
import { SessionTimeline } from '@/components/ui/SessionTimeline'
import { formatBytes, formatDateTime, timeAgo } from '@/lib/utils'
import { SEVERITY_ORDER, type Finding, type SessionSummary } from '@/api'
import { api } from '@/api'
import { cn } from '@/lib/utils'

export default function AnalysisDetailPage() {
  const { id = '' } = useParams()
  const { data, isLoading, isError, error, refetch } = useAnalysisDetail(id)
  const [slideId, setSlideId] = useState<string | null>(null)

  if (isLoading) return <LoadingState label="Loading analysis…" />
  if (isError) return <ErrorState message={(error as Error)?.message} onRetry={() => refetch()} />
  if (!data) return <ErrorState message="No data returned for this analysis." onRetry={() => refetch()} />

  const sevCounts = useMemo(() => {
    const counts: Partial<Record<string, number>> = {}
    for (const f of data.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1
    return counts
  }, [data.findings])

  return (
    <div className="relative">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4 border-b border-base-700/60 pb-4">
        <div className="min-w-0">
          <Link to="/app" className="inline-flex items-center gap-1 text-[11px] font-medium text-base-400 hover:text-accent">
            ← All analyses
          </Link>
          <h1 className="mt-1 truncate text-[18px] font-bold tracking-tight text-base-50">{data.filename}</h1>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-base-500">
            <CodeBlock className="text-[11px] text-base-400">{data.id.slice(0, 16)}…</CodeBlock>
            <span className="hidden sm:inline">·</span>
            <span>{formatDateTime(data.createdAt)} ({timeAgo(data.createdAt)})</span>
            <span className="hidden sm:inline">·</span>
            <span className="font-mono">{formatBytes(data.fileSize)}</span>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex gap-4 rounded-md border border-base-700/60 bg-base-850 px-3 py-2">
            <Stat label="Sessions" value={data.sessionsCount} />
            <Stat label="Findings" value={data.findingsCount} valueClassName={data.findingsCount ? 'text-sev-medium' : 'text-base-100'} />
            <Stat label="Anomalies" value={data.fleet.anomalyCount} valueClassName={data.fleet.anomalyCount ? 'text-sev-high' : 'text-base-100'} />
          </div>
          <ScoreGauge score={data.postureScore} size="md" />
          <ExportButtons id={id} />
        </div>
      </div>

      <div className="mb-4 flex flex-wrap gap-1.5">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5 rounded-full border border-base-700/60 bg-base-850 px-2.5 py-1">
            <SeverityBadge severity={s} className="text-[10px] leading-none" />
            <span className="font-mono text-[12px] font-semibold tabular-nums text-base-200">{sevCounts[s] ?? 0}</span>
          </span>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Reconstructed sessions" subtitle={`${data.sessionsCount} total · click to inspect`} className="xl:col-span-1">
          <SessionTable sessions={data.summaries} analysisId={id} onSelect={setSlideId} />
          <p className="mt-2 text-center font-mono text-[11px] text-base-500">Rows are sticky-header, sortable, and severity-coded on the left border. Selecting a row opens a slide-over without leaving the analysis.</p>
        </Panel>

        <Panel title="Findings" subtitle={`${data.findings.length} prioritized by severity`} className="xl:col-span-1">
          <FindingsList findings={data.findings} />
        </Panel>
      </div>

      {slideId && (
        <SlideOver sessionId={slideId} analysisId={id} onClose={() => setSlideId(null)} />
      )}
    </div>
  )
}

function SlideOver({ sessionId, analysisId, onClose }: { sessionId: string; analysisId: string; onClose: () => void }) {
  const { data, isLoading } = useSessionDetail(analysisId, sessionId)
  useEffect(() => {
    const onEsc = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onEsc)
    return () => window.removeEventListener('keydown', onEsc)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-base-950/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative flex h-full w-full max-w-[720px] flex-col overflow-hidden rounded-l-lg border-l border-base-700 bg-base-900 shadow-2xl animate-slide-in">
        <div className="flex items-center justify-between border-b border-base-700/60 bg-base-850 px-4 py-3">
          <div className="min-w-0">
            <div className="font-mono text-xs text-base-400">Session · {sessionId.slice(0, 16)}…</div>
            <div className="truncate font-mono text-sm text-base-100">{data?.fiveTuple ?? sessionId}</div>
          </div>
          <div className="flex items-center gap-2">
            <Link to={`/app/analyses/${analysisId}/sessions/${sessionId}`} className="rounded border border-base-600 px-2.5 py-1 text-xs font-medium text-base-300 hover:bg-base-800">
              Full page →
            </Link>
            <button onClick={onClose} className="rounded bg-base-800 px-2.5 py-1 text-sm text-base-300 hover:bg-base-700" aria-label="Close">
              ✕
            </button>
          </div>
        </div>
        <div className="flex-1 overflow-auto p-4">
          {isLoading ? (
            <div className="space-y-2">
              <div className="h-4 w-3/4 animate-pulse rounded bg-base-800" />
              <div className="h-32 animate-pulse rounded bg-base-800" />
            </div>
          ) : !data ? (
            <EmptyState title="No session data" hint="The session could not be loaded." />
          ) : (
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <Panel title="Handshake" padded>
                  <div className="space-y-2 font-mono text-xs text-base-300">
                    <div>TLS <b className="text-base-100">{data.tlsVersion ?? '—'}</b> · Cipher <b className="text-base-100">{data.cipher ?? '—'}</b></div>
                    <div>Strength <b className={data.cipherStrength != null && data.cipherStrength < 0.6 ? 'text-sev-high' : 'text-positive'}>{data.cipherStrength?.toFixed(2) ?? '—'}</b> · PFS <b className={data.pfsSupported ? 'text-positive' : 'text-sev-high'}>{data.pfsSupported == null ? '—' : data.pfsSupported ? 'yes' : 'no'}</b></div>
                    <div>Risk <b className="text-sev-medium">{data.riskScore ?? '—'}</b> · Anomaly <b className={data.isAnomaly ? 'text-sev-high' : 'text-positive'}>{data.isAnomaly ? 'yes' : 'no'}</b></div>
                  </div>
                </Panel>
                <Panel title="SHAP" padded>
                  <ExplanationPanel rows={data.shap} />
                </Panel>
              </div>
              <Panel title="Certificate chain">
                <CertChainViewer chain={data.certChain} chainResult={data.chainResult} />
              </Panel>
              <Panel title="Timeline" subtitle="plaintext → STARTTLS → handshake">
                <SessionTimeline events={data.timeline} />
              </Panel>
            </div>
          )}
        </div>
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
    <div className="flex flex-wrap items-center gap-1.5">
      {formats.map(({ fmt, label }) => (
        <a
          key={fmt}
          href={api.reportUrl(id, fmt)}
          target="_blank"
          rel="noreferrer"
          className="rounded border border-base-600 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-base-300 hover:border-accent/50 hover:text-accent transition-colors"
        >
          {label}
        </a>
      ))}
      <button
        onClick={() => {
          navigator.clipboard.writeText(id)
          setCopy(true)
          setTimeout(() => setCopy(false), 1500)
        }}
        className="rounded border border-base-600 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-base-300 hover:border-accent/50 hover:text-accent transition-colors"
      >
        {copy ? '✓ copied' : 'Copy id'}
      </button>
    </div>
  )
}

function SessionTable({ sessions, onSelect }: { sessions: SessionSummary[]; analysisId: string; onSelect: (id: string) => void }) {
  const [protocol, setProtocol] = useState<string>('all')

  const rows = useMemo(() => (protocol === 'all' ? sessions : sessions.filter((s) => s.protocol === protocol)), [sessions, protocol])
  const protocols = useMemo(() => [...new Set(sessions.map((s) => s.protocol))], [sessions])

  const columns: Column<SessionSummary>[] = [
    {
      key: 'fiveTuple',
      header: 'Connection',
      sortValue: (r) => r.fiveTuple,
      render: (r) => (
        <button onClick={() => onSelect(r.id)} className="text-left font-mono text-[11px] leading-tight text-base-100 hover:text-accent" title={r.fiveTuple}>
          <span className="block max-w-[220px] truncate">{r.fiveTuple}</span>
          <span className="text-[10px] text-base-500">{r.id.slice(0, 8)}</span>
        </button>
      ),
    },
    {
      key: 'protocol',
      header: 'Proto',
      sortValue: (r) => r.protocol,
      render: (r) => <CodeBlock className="text-[11px] text-accent">{r.protocol}</CodeBlock>,
    },
    {
      key: 'tls',
      header: 'TLS',
      sortValue: (r) => r.tlsVersion ?? '',
      render: (r) => (
        <div className="leading-tight">
          <CodeBlock className="text-[11px] text-base-200">{r.tlsVersion ?? '—'}</CodeBlock>
          <div className="font-mono text-[10px] text-base-500">{r.isStarttls ? 'STARTTLS' : 'implicit'}</div>
        </div>
      ),
    },
    {
      key: 'cipher',
      header: 'Cipher',
      sortValue: (r) => r.cipher ?? '',
      render: (r) => <CodeBlock className="max-w-[160px] truncate text-[11px] text-base-200">{r.cipher ?? '—'}</CodeBlock>,
    },
    {
      key: 'findingCount',
      header: 'Fnd',
      sortValue: (r) => r.findingCount,
      numeric: true,
      render: (r) => <span className="font-mono text-xs tabular-nums text-base-200">{r.findingCount}</span>,
    },
    {
      key: 'severity',
      header: 'Max',
      sortValue: (r) => SEVERITY_ORDER[r.maxSeverity],
      render: (r) => <SeverityBadge severity={r.maxSeverity} pulse={r.maxSeverity === 'critical'} />,
    },
    {
      key: 'score',
      header: 'Score',
      sortValue: (r) => r.riskScore ?? -1,
      numeric: true,
      render: (r) => (
        <span className={cn('font-mono text-xs font-bold tabular-nums', r.riskScore != null && r.riskScore >= 60 ? 'text-sev-high' : r.riskScore != null && r.riskScore >= 30 ? 'text-sev-medium' : 'text-sev-low')}>
          {r.riskScore ?? '—'}
        </span>
      ),
    },
  ]

  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-base-400">Filter</span>
        <select value={protocol} onChange={(e) => setProtocol(e.target.value)} className="rounded border border-base-600 bg-base-900 px-2 py-1 text-xs text-base-200">
          <option value="all">all protocols</option>
          {protocols.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <span className="ml-auto hidden font-mono text-[11px] text-base-500 sm:inline">{rows.length} sessions</span>
      </div>
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} dense stickyHeader severityKey={(r) => r.maxSeverity} />
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
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
          <button
            key={s}
            onClick={() => setSeverityFilter(s)}
            className={cn(
              'rounded-full border px-2.5 py-1 text-[11px] font-semibold capitalize transition-colors',
              severityFilter === s ? 'border-accent bg-accent text-base-950' : 'border-base-700 bg-base-800 text-base-400 hover:text-base-200',
            )}
          >
            {s}
          </button>
        ))}
      </div>

      {rows.length === 0 ? (
        <EmptyState title="No findings" hint="No rule triggered for this filter. Try “all” or check the session timeline for handshake details." />
      ) : (
        <ul className="max-h-[560px] divide-y divide-base-800 overflow-auto">
          {rows.map((f) => (
            <li key={f.id} className={cn('group py-3 transition-colors hover:bg-base-800/40', f.severity === 'critical' && 'bg-sev-critical/5')}>
              <div className="flex items-start gap-2.5">
                <SeverityBadge severity={f.severity} pulse={f.severity === 'critical'} className="mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="text-[13px] font-semibold leading-tight text-base-100">{f.title}</span>
                    <CodeBlock className="shrink-0 text-[10px] text-base-500">{f.ruleId}</CodeBlock>
                  </div>
                  <p className="mt-1 text-[12px] leading-relaxed text-base-300">{f.description}</p>
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
                    <span className="inline-flex items-center gap-1 rounded bg-base-800 px-1.5 py-0.5 font-mono text-base-300">
                      {f.session.fiveTuple}
                    </span>
                    {f.reference && <span className="font-mono text-accent/80">{f.reference}</span>}
                    {f.kind !== 'rule' && <span className="rounded bg-base-700 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-base-200">{f.kind}</span>}
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
