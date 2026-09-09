import React from 'react'

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="rounded-md border border-base-700/60 bg-base-850 p-6">
      <div className="flex items-center gap-3 text-sm text-base-400">
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-base-600 border-t-accent" />
        {label}
      </div>
      {/* skeleton rows */}
      <div className="mt-4 space-y-2">
        <div className="h-3 rounded bg-base-800 animate-pulse" style={{ background: 'linear-gradient(90deg, #1a222d 25%, #273442 50%, #1a222d 75%)', backgroundSize: '200% 100%', animation: 'shimmer 1.4s infinite' }} />
        <div className="h-3 w-5/6 rounded bg-base-800 animate-pulse" />
        <div className="h-3 w-3/4 rounded bg-base-800 animate-pulse" />
      </div>
    </div>
  )
}

export function ErrorState({
  message,
  onRetry,
}: {
  message?: string | null
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col gap-3 rounded-md border border-sev-critical/30 bg-sev-critical/10 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-start gap-2.5">
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-sev-critical/20 text-sev-critical">!</span>
        <div>
          <div className="text-sm font-semibold text-sev-critical">Couldn’t load data</div>
          <div className="mt-0.5 max-w-[560px] text-xs leading-relaxed text-base-400">{message || 'An unexpected error occurred. This is not a finding — it’s a platform error.'}</div>
        </div>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="shrink-0 rounded border border-sev-critical/40 bg-sev-critical px-3 py-1.5 text-xs font-semibold text-white hover:bg-sev-critical/90"
        >
          Retry
        </button>
      )}
    </div>
  )
}

export function EmptyState({ icon, title, hint, action }: { icon?: React.ReactNode; title: string; hint?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full border border-dashed border-base-600 bg-base-900 text-base-400">
        {icon ?? <span className="font-mono text-lg">∅</span>}
      </div>
      <div>
        <p className="text-sm font-semibold text-base-200">{title}</p>
        {hint && <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-base-400">{hint}</p>}
      </div>
      {action && <div className="mt-1">{action}</div>}
    </div>
  )
}

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className,
  padded = true,
}: {
  title?: React.ReactNode
  subtitle?: React.ReactNode
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
  padded?: boolean
}) {
  return (
    <section className={'overflow-hidden rounded-md border border-base-600/60 bg-base-850 shadow-panel ' + (className ?? '')}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-base-700/60 bg-base-800/60 px-3 py-2.5">
          <div className="flex min-w-0 items-baseline gap-2">
            {title && <h2 className="truncate text-[13px] font-semibold text-base-100">{title}</h2>}
            {subtitle && <span className="truncate text-[11px] text-base-400">{subtitle}</span>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? 'p-3' : ''}>{children}</div>
    </section>
  )
}

export function Stat({ label, value, valueClassName, hint }: {
  label: string
  value: React.ReactNode
  valueClassName?: string
  hint?: string
}) {
  return (
    <div className="min-w-[80px]" title={hint}>
      <div className="text-[10px] font-semibold uppercase tracking-wider text-base-400">{label}</div>
      <div className={'mt-0.5 text-lg font-bold tabular-nums leading-tight transition-colors duration-300 ' + (valueClassName ?? 'text-base-100')}>
        {value}
      </div>
    </div>
  )
}

export function EvidenceJson({ data }: { data: Record<string, unknown> | null }) {
  if (!data || !Object.keys(data).length) return null
  return (
    <pre className="scrollbar-thin mt-1 max-h-40 overflow-auto rounded border border-base-700/60 bg-base-950 p-2 font-mono text-[11px] leading-relaxed text-base-300">
      {JSON.stringify(data, null, 1)}
    </pre>
  )
}
