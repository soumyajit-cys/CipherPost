import type { ShapRow } from '@/api'
import { CodeBlock } from './primitives'

export function ExplanationPanel({
  rows,
  emptyLabel = 'No SHAP contributions recorded for this session.',
}: {
  rows: ShapRow[]
  emptyLabel?: string
}) {
  if (!rows.length) {
    return (
      <div className="flex flex-col items-center gap-2 py-10 text-center">
        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-dashed border-base-600 bg-base-900">
          <span className="font-mono text-sm text-base-500">◈</span>
        </div>
        <p className="text-sm font-medium text-base-300">{emptyLabel}</p>
        <p className="max-w-sm text-xs leading-relaxed text-base-500">
          SHAP values appear once the risk model has enough fleet context. Every bar shows how a single feature pushed the score up (amber/red) or down (blue).
        </p>
      </div>
    )
  }

  const sorted = [...rows].sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact)).slice(0, 12)
  const maxAbs = Math.max(...sorted.map((r) => Math.abs(r.impact)), 0.01)

  // Split into positive / negative for legend
  const pos = sorted.filter((r) => r.impact >= 0)
  const neg = sorted.filter((r) => r.impact < 0)

  return (
    <div>
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-base-400">Feature impact — SHAP</h3>
        <span className="flex items-center gap-3 text-[11px]">
          <span className="inline-flex items-center gap-1 text-sev-high"><span className="h-2 w-3 rounded-sm bg-sev-high" /> pushes risk up</span>
          <span className="inline-flex items-center gap-1 text-positive"><span className="h-2 w-3 rounded-sm bg-positive" /> pulls risk down</span>
        </span>
      </div>

      <div className="space-y-2">
        {sorted.map((r) => {
          const positive = r.impact >= 0
          const pct = (Math.abs(r.impact) / maxAbs) * 100
          return (
            <div key={r.feature} className="group">
              <div className="mb-1 flex items-baseline justify-between gap-2">
                <CodeBlock className="truncate text-[11px] text-base-300 group-hover:text-base-100">{r.feature}</CodeBlock>
                <span className={'shrink-0 font-mono text-[11px] font-semibold tabular-nums ' + (positive ? 'text-sev-high' : 'text-positive')}>
                  {positive ? '+' : ''}{r.impact.toFixed(3)}
                </span>
              </div>
              <div className="relative h-6 overflow-hidden rounded bg-base-900 p-1">
                {/* center line */}
                <div className="absolute left-1/2 top-1 bottom-1 w-px bg-base-700/80" />
                <div
                  className={'absolute top-1 bottom-1 rounded-sm transition-all duration-500 ' + (positive ? 'left-1/2 bg-gradient-to-r from-sev-medium to-sev-high' : 'right-1/2 bg-gradient-to-l from-positive/80 to-positive')}
                  style={{ width: `${pct / 2}%` }}
                />
                <span className="absolute inset-0 flex items-center px-2 font-mono text-[10px] text-base-500">
                  value {typeof r.value === 'number' ? r.value.toFixed(2) : String(r.value ?? '—')}
                </span>
              </div>
            </div>
          )
        })}
      </div>

      <div className="mt-4 rounded border border-base-700/60 bg-base-900 px-3 py-2 text-[11px] leading-relaxed text-base-400">
        <span className="font-semibold text-base-300">How to read:</span> bar length = SHAP magnitude for this session. Bars to the right of center pushed the score higher; bars to the left pulled it lower. Method <CodeBlock className="text-[10px]">shap.TreeExplainer</CodeBlock> · values are relative within this session.
      </div>
    </div>
  )
}
