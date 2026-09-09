import type { CertInfo } from '@/api'
import { CodeBlock, KeyValue } from './primitives'
import { formatDateTime } from '@/lib/utils'
import { cn } from '@/lib/utils'

export function CertChainViewer({ chain, chainResult }: { chain: CertInfo[]; chainResult: string }) {
  if (!chain.length) {
    return (
      <div className="flex flex-col items-center gap-2 py-10 text-center">
        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-dashed border-base-600 bg-base-900">
          <span className="font-mono text-sm text-base-500">⬣</span>
        </div>
        <p className="text-sm font-medium text-base-300">No certificate chain captured</p>
        <p className="max-w-sm text-xs leading-relaxed text-base-500">
          This session did not present a certificate — either it was plaintext, the handshake was incomplete, or the capture window missed the ServerHello.
        </p>
      </div>
    )
  }

  const overallOk = chainResult === 'ok'

  return (
    <div>
      {/* Trust verdict — hierarchy: icon + label + detail */}
      <div className={cn('flex items-center gap-3 rounded-md border px-3 py-2.5', overallOk ? 'border-positive/30 bg-positive/10' : 'border-sev-high/30 bg-sev-high/10')}>
        <span className={cn('flex h-7 w-7 shrink-0 items-center justify-center rounded-full border text-[13px]', overallOk ? 'border-positive/40 bg-positive/20 text-positive' : 'border-sev-high/40 bg-sev-high/20 text-sev-high')}>
          {overallOk ? '✓' : '✕'}
        </span>
        <div className="min-w-0">
          <div className={cn('text-[13px] font-semibold', overallOk ? 'text-positive' : 'text-sev-high')}>
            {overallOk ? 'Chain trusted' : `Chain ${chainResult}`}
          </div>
          <div className="text-xs leading-relaxed text-base-400">
            {overallOk ? 'Validated against the configured trust store — issuer chains to a trusted root.' : 'Verification against the trust store failed. Inspect the leaf and intermediate details below.'}
          </div>
        </div>
        <span className={cn('ml-auto hidden shrink-0 rounded px-2 py-1 font-mono text-[11px] sm:inline', overallOk ? 'bg-positive/20 text-positive' : 'bg-sev-high/20 text-sev-high')}>
          {chain.length} cert{chain.length !== 1 ? 's' : ''} · depth {chain.length - 1}
        </span>
      </div>

      {/* Vertical spine */}
      <div className="relative mt-4 pl-6">
        {/* spine line */}
        <div className="absolute left-[11px] top-2 bottom-2 w-px bg-base-700/60" aria-hidden />
        <div className="space-y-3">
          {chain.map((c, i) => (
            <CertNode key={i} cert={c} index={i} count={chain.length} />
          ))}
        </div>
      </div>
    </div>
  )
}

function CertNode({ cert, index, count }: { cert: CertInfo; index: number; count: number }) {
  const isLeaf = index === 0
  const isRoot = index === count - 1
  const role = isLeaf ? 'leaf' : isRoot ? 'root' : `intermediate ${index}`
  const hasProblem = cert.expired || cert.selfSigned || cert.weakSignature || cert.shortKey || (cert.chainResult !== 'ok' && cert.chainResult !== 'unknown' && cert.chainResult !== '')

  const dotColor = cert.expired ? 'bg-sev-critical border-sev-critical' : hasProblem ? 'bg-sev-high border-sev-high' : 'bg-positive border-positive'
  const ringColor = cert.expired ? 'ring-sev-critical/20' : hasProblem ? 'ring-sev-high/20' : 'ring-positive/20'

  const flags: { label: string; tone: string }[] = []
  if (cert.expired) flags.push({ label: 'EXPIRED', tone: 'bg-sev-critical text-white' })
  if (cert.notYetValid) flags.push({ label: 'NOT YET VALID', tone: 'bg-sev-medium text-white' })
  if (cert.selfSigned) flags.push({ label: 'SELF-SIGNED', tone: 'bg-sev-medium text-white' })
  if (cert.weakSignature) flags.push({ label: `WEAK SIG · ${cert.signatureAlg}`, tone: 'bg-sev-high text-white' })
  if (cert.shortKey) flags.push({ label: `SHORT KEY · ${cert.pubkeyBits}b`, tone: 'bg-sev-high text-white' })
  if (cert.daysRemaining != null && cert.daysRemaining < 30 && !cert.expired) flags.push({ label: `EXPIRES IN ${cert.daysRemaining}d`, tone: 'bg-sev-medium text-white' })
  if (cert.chainResult !== 'ok' && cert.chainResult !== 'unknown' && cert.chainResult !== '') flags.push({ label: cert.chainResult.toUpperCase(), tone: 'bg-base-700 text-base-100' })

  return (
    <div className="relative">
      {/* node dot */}
      <span className={cn('absolute -left-[18px] top-4 h-3 w-3 rounded-full border-2 bg-base-950 ring-4', dotColor, ringColor)} />
      <div className={cn('overflow-hidden rounded-md border bg-base-850 shadow-sm transition-colors hover:border-base-600', isLeaf ? 'border-base-600/60' : 'border-base-700/50')}>
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-base-700/60 bg-base-800/60 px-3 py-2">
          <div className="flex items-center gap-2 min-w-0">
            <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide', isLeaf ? 'bg-accent/15 text-accent border border-accent/30' : 'bg-base-700 text-base-300')}>
              {role}
            </span>
            <span className="truncate font-mono text-[12px] font-medium text-base-100">{cert.subject}</span>
            {!hasProblem && <span className="rounded bg-positive/15 px-1.5 py-0.5 text-[10px] font-bold tracking-wide text-positive">OK</span>}
          </div>
          <div className="flex flex-wrap gap-1">
            {flags.map((f, i) => (
              <span key={i} className={cn('rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wide', f.tone)}>
                {f.label}
              </span>
            ))}
          </div>
        </div>

        <div className="grid gap-4 p-3 sm:grid-cols-2">
          <div className="space-y-1">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-base-400">Identity</div>
            <KeyValue k="Issuer" v={<CodeBlock className="text-[11px]">{cert.issuer}</CodeBlock>} />
            <KeyValue k="Serial" v={<CodeBlock className="text-[11px]">{cert.serial}</CodeBlock>} />
            <KeyValue k="SANs" v={<span className="font-mono text-[11px] text-base-300">{cert.sans.join(' · ') || '—'}</span>} />
          </div>
          <div className="space-y-1">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-base-400">Cryptography</div>
            <KeyValue k="Public key" v={<CodeBlock className="text-[11px]">{cert.pubkeyAlg} {cert.pubkeyBits ? `${cert.pubkeyBits}b` : ''}</CodeBlock>} />
            <KeyValue k="Signature" v={<CodeBlock className="text-[11px]">{cert.signatureAlg}</CodeBlock>} />
            <KeyValue
              k="Validity"
              v={
                <span className={cn('font-mono text-[11px]', cert.expired ? 'text-sev-critical' : 'text-base-300')}>
                  {formatDateTime(cert.notBefore)} → {formatDateTime(cert.notAfter)}
                  {cert.daysValid != null && <span className="text-base-500"> · {cert.daysValid}d</span>}
                </span>
              }
            />
          </div>
        </div>
      </div>
    </div>
  )
}
