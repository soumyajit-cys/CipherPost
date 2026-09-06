import type { ShapRow } from '@/api'
import { CodeBlock } from './primitives'

/**
 * SHAP explanation panel: per-feature contribution bars showing what drove
 * a session's ML risk score / anomaly flag. Positive impact → pushed score
 * up (red), negative → pulled it down (green).
 */
export function ExplanationPanel({
  rows,
  emptyLabel = 'No SHAP contributions recorded for this session.',
}: {
  rows: ShapRow[]
  emptyLabel?: string
}) {
  if (!rows.length) {
    return <p className="py-4 text-center text-sm text-base-400">{emptyLabel}</p>
  }

  const sorted = [...rows].sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact)).slice(0, 12)
  const maxAbs = Math.max(...sorted.map((r) => Math.abs(r.impact)), 0.01)

  return (
    <div className="space-y-1.5">
      <div className="border-b border-base-600/50 pb-1 text-[11px] uppercase tracking-wider text-base-400">
        ML risk contribution — how each feature moved the score
      </div>
      {sorted.map((r) => {
        const positive = r.impact >= 0
        const pct = (Math.abs(r.impact) / maxAbs) * 100
        return (
          <div key={r.feature} className="group" title={r.feature}>
            <div className="mb-0.5 flex items-baseline justify-between gap-2">
              <CodeBlock className="text-[11px] truncate text-base-300 group-hover:text-base-100">
                {r.feature}
              </CodeBlock>
              <span
                className={
                  'shrink-0 font-mono text-[11px] tabular-nums ' +
                  (positive ? 'text-sev-high' : 'text-positive')
                }
              >
                {positive ? '+' : ''}{r.impact.toFixed(3)}
              </span>
            </div>
            <div className="relative h-1.5 overflow-hidden rounded-sm bg-base-800">
              <div
                className={
                  'absolute top-0 h-full rounded-sm ' +
                  (positive ? 'left-1/2 bg-sev-high/70' : 'right-1/2 bg-positive/70')
                }
                style={{ width: `${pct / 2}%` }}
              />
              <div className="absolute left-1/2 top-0 h-full w-px bg-base-600/60" />
            </div>
          </div>
        )
      })}
      <p className="pt-1 text-[11px] text-base-400">
        Values are SHAP magnitudes with the <CodeBlock className="text-[10px]">method=score</CodeBlock>{' '}
        model; bars are relative within this session.
      </p>
    </div>
  )
}