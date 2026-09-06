import React from 'react'

/** Structured state handling for every data view — no silent failures. */
export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 px-2 py-6 text-sm text-base-400">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-base-500 border-t-accent" />
      {label}
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
    <div className="flex items-center justify-between gap-3 rounded border border-sev-critical/40 bg-sev-critical/10 px-3 py-2.5">
      <span className="text-sm text-sev-critical">
        <span className="font-semibold">Error:</span>{' '}
        {message || 'Failed to load data'}
      </span>
      {onRetry && (
        <button
          onClick={onRetry}
          className="rounded border border-sev-critical/50 px-2 py-1 text-xs font-semibold text-sev-critical hover:bg-sev-critical/10"
        >
          Retry
        </button>
      )}
    </div>
  )
}

export function EmptyState({ icon, title, hint }: { icon?: React.ReactNode; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1.5 py-10 text-center">
      {icon && <div className="text-2xl opacity-60">{icon}</div>}
      <p className="text-sm font-medium text-base-300">{title}</p>
      {hint && <p className="text-xs text-base-400">{hint}</p>}
    </div>
  )
}

/** Wrap children in a panel with header + optional right-side actions. */
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
    <section className={'overflow-hidden rounded-md border border-base-600/60 bg-base-850 ' + (className ?? '')}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-base-600/60 bg-base-800/60 px-3 py-2">
          <div className="flex items-baseline gap-2 min-w-0">
            <h2 className="truncate text-[13px] font-semibold text-base-100">{title}</h2>
            {subtitle && <span className="truncate text-[11px] text-base-400">{subtitle}</span>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? 'p-3' : ''}>{children}</div>
    </section>
  )
}

/** Small monospace stat cell used in dense headers/summaries. */
export function Stat({ label, value, valueClassName, hint }: {
  label: string
  value: React.ReactNode
  valueClassName?: string
  hint?: string
}) {
  return (
    <div className="min-w-[80px]" title={hint}>
      <div className="text-[10px] uppercase tracking-wider text-base-400">{label}</div>
      <div className={'text-lg font-bold tabular-nums leading-tight ' + (valueClassName ?? 'text-base-100')}>
        {value}
      </div>
    </div>
  )
}

/** Render a JSX/ReactNode tree of an evidence object in a compact <pre>. */
export function EvidenceJson({ data }: { data: Record<string, unknown> | null }) {
  if (!data || !Object.keys(data).length) return null
  return (
    <pre className="scrollbar-thin mt-1 overflow-x-auto rounded bg-base-900 p-2 font-mono text-[11px] leading-relaxed text-base-300">
      {JSON.stringify(data, null, 1)}
    </pre>
  )
}