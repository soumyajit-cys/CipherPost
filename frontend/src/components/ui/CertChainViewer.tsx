import type { CertInfo } from '@/api'
import { CodeBlock, KeyValue } from './primitives'
import { formatDateTime } from '@/lib/utils'
import { cn } from '@/lib/utils'

/**
 * Certificate chain viewer: each cert in the chain with subject, issuer,
 * validity (flag expired/expiring soon), key algo + length, signature algo,
 * self-signed / untrusted flags.
 */
export function CertChainViewer({ chain, chainResult }: { chain: CertInfo[]; chainResult: string }) {
  if (!chain.length) {
    return <p className="py-3 text-center text-sm text-base-400">No certificate chain captured.</p>
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-wider text-base-400">Certificate chain</span>
        <span className={cn(
          'rounded border px-1.5 py-px font-mono text-[11px]',
          chainResult === 'ok'
            ? 'border-positive/40 bg-positive/10 text-positive'
            : 'border-sev-high/50 bg-sev-high/10 text-sev-high',
        )}>
          {chainResult}
        </span>
      </div>
      {chain.map((c, i) => (
        <CertCard key={i} cert={c} index={i} isLeaf={i === 0} count={chain.length} />
      ))}
    </div>
  )
}

function CertCard({ cert, index, isLeaf, count }: { cert: CertInfo; index: number; isLeaf: boolean; count: number }) {
  const flags: { label: string; cls: string }[] = []
  if (cert.expired) flags.push({ label: 'EXPIRED', cls: 'bg-sev-critical/15 text-sev-critical border-sev-critical/40' })
  if (cert.notYetValid) flags.push({ label: 'NOT YET VALID', cls: 'bg-sev-medium/15 text-sev-medium border-sev-medium/40' })
  if (cert.selfSigned) flags.push({ label: 'SELF-SIGNED', cls: 'bg-sev-medium/15 text-sev-medium border-sev-medium/40' })
  if (cert.weakSignature) flags.push({ label: `WEAK SIG: ${cert.signatureAlg}`, cls: 'bg-sev-high/15 text-sev-high border-sev-high/40' })
  if (cert.shortKey) flags.push({ label: `SHORT KEY: ${cert.pubkeyBits}b`, cls: 'bg-sev-high/15 text-sev-high border-sev-high/40' })
  if (cert.daysRemaining != null && cert.daysRemaining < 90 && !cert.expired)
    flags.push({ label: `EXPIRES IN ${cert.daysRemaining}d`, cls: 'bg-sev-medium/15 text-sev-medium border-sev-medium/40' })
  if (cert.chainResult !== 'ok' && cert.chainResult !== 'unknown' && cert.chainResult !== '')
    flags.push({ label: cert.chainResult.toUpperCase(), cls: 'bg-sev-high/15 text-sev-high border-sev-high/40' })

  const role = isLeaf ? 'leaf' : index === count - 1 ? 'root' : 'intermediate'

  return (
    <div className={'rounded-md border border-base-600/60 ' + (isLeaf ? 'bg-base-800/70' : 'bg-base-850')}>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-base-600/40 px-2.5 py-1.5">
        <div className="flex items-center gap-2 font-mono text-[12px] text-base-100">
          <span className={'rounded px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide ' +
            (role === 'leaf' ? 'bg-accent/15 text-accent' : 'bg-base-600/40 text-base-300')}>
            {role}
          </span>
          <span className="truncate">{cert.subject}</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {flags.length
            ? flags.map((f, i) => (
                <span key={i} className={cn('rounded border px-1.5 py-px text-[10px] font-bold', f.cls)}>
                  {f.label}
                </span>
              ))
            : <span className="rounded border border-positive/40 bg-positive/10 px-1.5 py-px text-[10px] font-bold text-positive">OK</span>}
        </div>
      </div>
      <div className="grid grid-cols-1 gap-x-6 px-2.5 py-1.5 sm:grid-cols-2">
        <div>
          <KeyValue k="Issuer" v={<CodeBlock>{cert.issuer}</CodeBlock>} mono />
          <KeyValue
            k="Validity"
            v={
              <span className="font-mono text-[11px] text-base-300">
                {formatDateTime(cert.notBefore)} → {formatDateTime(cert.notAfter)}
                {cert.daysValid != null && <span className="text-base-400"> ({cert.daysValid}d)</span>}
              </span>
            }
          />
          <KeyValue k="Serial" v={<CodeBlock>{cert.serial}</CodeBlock>} />
        </div>
        <div>
          <KeyValue
            k="Public key"
            v={
              <CodeBlock>
                {cert.pubkeyAlg} {cert.pubkeyBits ? `${cert.pubkeyBits}b` : ''}
              </CodeBlock>
            }
          />
          <KeyValue k="Signature" v={<CodeBlock>{cert.signatureAlg}</CodeBlock>} />
          <KeyValue
            k="SANs"
            v={<span className="font-mono text-[11px] text-base-300">{cert.sans.join(' · ') || '—'}</span>}
          />
        </div>
      </div>
    </div>
  )
}