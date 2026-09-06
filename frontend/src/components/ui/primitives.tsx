import { cn } from '@/lib/utils'

// ── SeverityBadge ──────────────────────────────────────────────────────────

const SEV_STYLES = {
  critical: 'bg-sev-critical/15 text-sev-critical border-sev-critical/40',
  high: 'bg-sev-high/15 text-sev-high border-sev-high/40',
  medium: 'bg-sev-medium/15 text-sev-medium border-sev-medium/40',
  low: 'bg-sev-low/15 text-sev-low border-sev-low/40',
  info: 'bg-sev-info/15 text-sev-info border-sev-info/40',
  none: 'bg-transparent text-base-400 border-base-500/40',
} as const

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const s = (severity || 'none') as keyof typeof SEV_STYLES
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-px text-[11px] font-semibold uppercase tracking-wide',
        SEV_STYLES[s] ?? SEV_STYLES.none,
        className,
      )}
    >
      {severity || '—'}
    </span>
  )
}

// ── ScoreGauge ──────────────────────────────────────────────────────────────

/** Color derived ONLY from the risk score: green → amber → red. */
export function scoreColor(score: number | null | undefined): {
  text: string
  bg: string
  ring: string
} {
  if (score == null) return { text: 'text-base-400', bg: 'bg-base-600', ring: 'border-base-500/60' }
  if (score < 30) return { text: 'text-sev-low', bg: 'bg-sev-low', ring: 'border-sev-low/60' }
  if (score < 60) return { text: 'text-sev-medium', bg: 'bg-sev-medium', ring: 'border-sev-medium/60' }
  return { text: 'text-sev-high', bg: 'bg-sev-high', ring: 'border-sev-high/60' }
}

export function scoreColorHex(score: number | null | undefined): string {
  const c = scoreColor(score)
  return c.bg
}

export function ScoreGauge({
  score,
  size = 'md',
  showLabel = true,
}: {
  score: number | null | undefined
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
}) {
  const s = score ?? 0
  const { text } = scoreColor(score)
  const dim = size === 'lg' ? 'h-28 w-28 text-3xl' : size === 'sm' ? 'h-12 w-12 text-base' : 'h-20 w-20 text-xl'
  const ring = size === 'lg' ? '[&>span]:ring-4' : '[&>span]:ring-2'
  return (
    <div className="flex flex-col items-center gap-1">
      <div
        className={cn(
          'flex items-center justify-center rounded-full text-center',
          dim,
          'bg-base-850 border border-base-600/60 shadow-inner',
          ring,
        )}
        style={{ boxShadow: `inset 0 0 0 4px ${scoreColorHex(score)}22` }}
      >
        <span className={cn('font-bold tabular-nums leading-none', text)} style={{ textShadow: `0 0 18px ${scoreColorHex(score)}66` }}>
          {score == null ? '·' : s}
          {score != null && size !== 'sm' && showLabel && (
            <span className={cn('ml-px text-[0.45em] font-semibold', text)}>/100</span>
          )}
        </span>
      </div>
      {showLabel && size !== 'sm' && (
        <span className="text-[11px] uppercase tracking-wider text-base-400">posture</span>
      )}
    </div>
  )
}

// ── CodeBlock ───────────────────────────────────────────────────────────────

/** Monospace snippet for cipher names, hex, fingerprints, offsets. */
export function CodeBlock({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <code className={cn('font-mono text-[12px] text-base-200', className)}>
      {children}
    </code>
  )
}

// ── KeyValue ────────────────────────────────────────────────────────────────

export function KeyValue({
  k, v, mono, valueClassName, className,
}: {
  k: string
  v: React.ReactNode
  mono?: boolean
  valueClassName?: string
  className?: string
}) {
  return (
    <div className={cn('flex items-baseline justify-between gap-3 py-1', className)}>
      <span className="text-[11px] uppercase tracking-wider text-base-400 shrink-0">{k}</span>
      <span className={cn('text-[13px] text-right text-base-200 break-all', mono && 'font-mono text-[12px]', valueClassName)}>
        {v ?? '—'}
      </span>
    </div>
  )
}

// ── StatusDot ───────────────────────────────────────────────────────────────

export function StatusDot({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: 'bg-positive',
    processing: 'bg-accent animate-pulse',
    pending: 'bg-sev-medium',
    failed: 'bg-sev-critical',
  }
  return <span className={cn('inline-block h-2 w-2 rounded-full', map[status] ?? 'bg-base-500')} title={status} />
}