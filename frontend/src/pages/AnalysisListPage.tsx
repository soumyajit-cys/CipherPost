import { Link } from 'react-router-dom'
import { useAnalyses } from '@/hooks/useApi'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { ErrorState, EmptyState, LoadingState } from '@/components/ui/State'
import { SeverityBadge, ScoreGauge, StatusDot, CodeBlock } from '@/components/ui/primitives'
import { formatBytes, formatDateTime, timeAgo } from '@/lib/utils'
import { SEVERITY_ORDER, type AnalysisSummary } from '@/api'

export default function AnalysisListPage() {
  const { data, isLoading, isError, error, refetch } = useAnalyses()

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
            <Link to={`/analyses/${r.id}`} className="font-medium text-base-100 hover:text-accent">
              {r.filename}
            </Link>
            <div className="text-[11px] text-base-400">
              id:{' '}
              <CodeBlock className="text-[10px] text-base-400">{r.id}</CodeBlock>
            </div>
          </div>
        </div>
      ),
    },
    {
      key: 'createdAt',
      header: 'Uploaded',
      sortValue: (r) => r.createdAt,
      render: (r) => (
        <div>
          <div className="text-base-200">{formatDateTime(r.createdAt)}</div>
          <div className="text-[11px] text-base-400">{timeAgo(r.createdAt)}</div>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      sortValue: (r) => r.status,
      render: (r) => (
        <span className="text-capitalize text-[12px] text-base-300">{r.status}</span>
      ),
    },
    {
      key: 'fileSize',
      header: 'Size',
      sortValue: (r) => r.fileSize,
      numeric: true,
      render: (r) => <CodeBlock className="text-base-300">{formatBytes(r.fileSize)}</CodeBlock>,
    },
    {
      key: 'sessionsCount',
      header: 'Sessions',
      sortValue: (r) => r.sessionsCount,
      numeric: true,
      render: (r) => <span className="cell-numeric text-base-200">{r.sessionsCount || '—'}</span>,
    },
    {
      key: 'findingsCount',
      header: 'Findings',
      sortValue: (r) => r.findingsCount,
      numeric: true,
      render: (r) => <span className="cell-numeric text-base-200">{r.findingsCount || 0}</span>,
    },
    {
      key: 'maxSeverity',
      header: 'Max Severity',
      sortValue: (r) => SEVERITY_ORDER[r.maxSeverity ?? 'none'],
      render: (r) => <SeverityBadge severity={r.maxSeverity ?? 'none'} />,
    },
    {
      key: 'postureScore',
      header: 'Posture',
      sortValue: (r) => r.postureScore ?? -1,
      numeric: true,
      render: (r) =>
        r.postureScore == null ? (
          <span className="text-base-400">—</span>
        ) : (
          <div className="flex items-center gap-2">
            <ScoreGauge score={r.postureScore} size="sm" showLabel={false} />
            <CodeBlock className="text-base-200">{r.postureScore}</CodeBlock>
          </div>
        ),
    },
  ]

  return (
    <div>
      <div className="mb-3 flex items-end justify-between">
        <div>
          <h1 className="text-lg font-bold text-base-50">Analyses</h1>
          <p className="text-[12px] text-base-400">
            Past email-traffic captures and their cryptographic posture assessments.
          </p>
        </div>
        <Link
          to="/upload"
          className="rounded border border-accent/50 bg-accent/10 px-3 py-1.5 text-[13px] font-semibold text-accent hover:bg-accent/20"
        >
          + New Analysis
        </Link>
      </div>

      <div className="overflow-hidden rounded-md border border-base-600/60 bg-base-850">
        <DataTable columns={columns} rows={data ?? []} rowKey={(r) => r.id} dense />
        {data?.length === 0 && (
          <EmptyState
            title="No analyses yet"
            hint="Upload a SMTP/IMAP/POP3 capture to get started."
          />
        )}
      </div>
    </div>
  )
}