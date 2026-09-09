import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAnalyses } from '@/hooks/useApi'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { ErrorState, EmptyState, LoadingState } from '@/components/ui/State'
import { SeverityBadge, ScoreGauge, StatusDot, CodeBlock } from '@/components/ui/primitives'
import { formatBytes, formatDateTime, timeAgo } from '@/lib/utils'
import { SEVERITY_ORDER, type AnalysisSummary } from '@/api'

export default function AnalysisListPage() {
  const { data, isLoading, isError, error, refetch } = useAnalyses()
  const [newIds, setNewIds] = useState<Set<string>>(new Set())
  const prev = useRef<Set<string>>(new Set())

  useEffect(() => {
    if (!data) return
    const ids = new Set(data.map((r) => r.id))
    const added = [...ids].filter((id) => !prev.current.has(id))
    if (added.length) {
      setNewIds(new Set(added))
      const t = setTimeout(() => setNewIds(new Set()), 1200)
      return () => clearTimeout(t)
    }
    prev.current = ids
  }, [data])

  if (isLoading) return <LoadingState label="Loading analyses…" />
  if (isError) return <ErrorState message={(error as Error)?.message} onRetry={() => refetch()} />

  const columns: Column<AnalysisSummary>[] = [
    {
      key: 'filename',
      header: 'Analysis',
      sortValue: (r) => r.filename,
      render: (r) => (
        <div className="flex items-center gap-2.5">
          <StatusDot status={r.status} />
          <div className="min-w-0">
            <Link to={`/app/analyses/${r.id}`} className="font-medium text-base-100 hover:text-accent">
              {r.filename}
            </Link>
            <div className="text-[11px] text-base-500">
              id: <CodeBlock className="text-[10px] text-base-500">{r.id.slice(0, 12)}</CodeBlock>
            </div>
          </div>
        </div>
      ),
    },
    {
      key: 'createdAt',
      header: 'Captured',
      sortValue: (r) => r.createdAt,
      render: (r) => (
        <div>
          <div className="text-base-200">{formatDateTime(r.createdAt)}</div>
          <div className="text-[11px] text-base-500">{timeAgo(r.createdAt)}</div>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      sortValue: (r) => r.status,
      render: (r) => (
        <span className="inline-flex items-center gap-1.5 text-[12px] capitalize text-base-300">
          <StatusDot status={r.status} /> {r.status}
        </span>
      ),
    },
    {
      key: 'fileSize',
      header: 'Size',
      sortValue: (r) => r.fileSize,
      numeric: true,
      render: (r) => <CodeBlock className="text-[11px] text-base-300">{formatBytes(r.fileSize)}</CodeBlock>,
    },
    {
      key: 'sessionsCount',
      header: 'Sessions',
      sortValue: (r) => r.sessionsCount,
      numeric: true,
      render: (r) => <span className="font-mono text-[12px] tabular-nums text-base-200">{r.sessionsCount ?? '—'}</span>,
    },
    {
      key: 'findingsCount',
      header: 'Findings',
      sortValue: (r) => r.findingsCount,
      numeric: true,
      render: (r) => <span className="font-mono text-[12px] font-medium tabular-nums text-base-200">{r.findingsCount || 0}</span>,
    },
    {
      key: 'maxSeverity',
      header: 'Max severity',
      sortValue: (r) => SEVERITY_ORDER[r.maxSeverity ?? 'none'],
      render: (r) => <SeverityBadge severity={r.maxSeverity ?? 'none'} pulse={r.maxSeverity === 'critical'} />,
    },
    {
      key: 'postureScore',
      header: 'Posture',
      sortValue: (r) => r.postureScore ?? -1,
      numeric: true,
      render: (r) =>
        r.postureScore == null ? (
          <span className="text-base-500">—</span>
        ) : (
          <span className="inline-flex items-center gap-2">
            <ScoreGauge score={r.postureScore} size="sm" showLabel={false} />
            <span className="font-mono text-[12px] font-bold tabular-nums text-base-100">{r.postureScore}</span>
          </span>
        ),
    },
  ]

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold tracking-tight text-base-50">Analyses</h1>
          <p className="max-w-[560px] text-[12px] leading-relaxed text-base-400">
            Past captures and live-ingested sessions — same pipeline, same severity semantics. New rows slide in; critical findings pulse once to draw attention.
          </p>
        </div>
        <Link
          to="/app/upload"
          className="inline-flex items-center gap-1.5 rounded bg-accent px-3.5 py-2 text-[13px] font-semibold text-base-950 hover:bg-accent/90 transition-colors"
        >
          + New capture
        </Link>
      </div>

      <div className="overflow-hidden rounded-md border border-base-600/60 bg-base-850 shadow-panel">
        <DataTable
          columns={columns}
          rows={data ?? []}
          rowKey={(r) => r.id}
          dense
          stickyHeader
          severityKey={(r) => r.maxSeverity ?? 'none'}
          newRowIds={newIds}
          emptyLabel="No analyses — upload a PCAP or start live capture"
        />
        {data?.length === 0 && (
          <div className="border-t border-base-700/60 p-6">
            <EmptyState
              title="No analyses yet"
              hint="Upload a SMTP/IMAP/POP3 capture, or switch to Live to watch the wire. The same forensic engine powers both."
              action={<Link to="/app/upload" className="rounded bg-accent px-3 py-1.5 text-sm font-semibold text-base-950 hover:bg-accent/90">Upload a capture</Link>}
            />
          </div>
        )}
      </div>

      <p className="mt-3 text-center font-mono text-[11px] text-base-500">
        Live: <span className="text-positive">Streaming</span> updates via SSE — this table will slide new analyses in without a refresh.
      </p>
    </div>
  )
}
