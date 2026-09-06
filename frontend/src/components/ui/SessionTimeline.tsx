import { cn } from '@/lib/utils'
import type { TimelineEvent } from '@/api'

/**
 * Protocol timeline: plaintext commands → STARTTLS transition → TLS
 * handshake records → session end. Rendered as a compact, monospace
 * event list like a protocol analyzer.
 */
export function SessionTimeline({ events }: { events: TimelineEvent[] }) {
  if (!events.length) {
    return <p className="py-4 text-center text-sm text-base-400">No captured events for this session.</p>
  }

  const colorFor = (type: TimelineEvent['type']) => {
    switch (type) {
      case 'starttls': return 'text-sev-medium'
      case 'tls': return 'text-accent'
      case 'client-command': return 'text-base-100'
      case 'plaintext-server': return 'text-base-300'
      default: return 'text-base-400'
    }
  }
  const dotFor = (type: TimelineEvent['type']) => {
    switch (type) {
      case 'starttls': return 'bg-sev-medium'
      case 'tls': return 'bg-accent'
      case 'client-command': return 'bg-base-200'
      default: return 'bg-base-500'
    }
  }

  return (
    <div className="scrollbar-thin overflow-x-auto">
      <ol className="relative font-mono text-[12px] leading-relaxed">
        {events.map((e, i) => (
          <li key={i} className="flex items-start gap-3 py-0.5">
            <span
              className={cn('mt-1.5 inline-block h-1.5 w-1.5 shrink-0 rounded-full', dotFor(e.type))}
            />
            <span className="w-10 shrink-0 text-right tabular-nums text-base-500">{e.offset}</span>
            <span className={cn('w-12 shrink-0 uppercase text-[10px] tracking-wide leading-4 text-base-500', colorFor(e.type))}>
              {e.direction === 'client' ? 'C→S' : 'S→C'}
            </span>
            <span className="flex-1">
              <span className={cn(colorFor(e.type))}>{e.summary}</span>
            </span>
          </li>
        ))}
      </ol>
    </div>
  )
}