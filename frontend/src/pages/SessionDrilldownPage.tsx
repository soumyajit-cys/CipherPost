import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useSessionDetail } from '@/hooks/useApi'
import { ErrorState, LoadingState, Panel } from '@/components/ui/State'
import { SeverityBadge, ScoreGauge, CodeBlock, KeyValue } from '@/components/ui/primitives'
import { SessionTimeline } from '@/components/ui/SessionTimeline'
import { ExplanationPanel } from '@/components/ui/ExplanationPanel'
import { CertChainViewer } from '@/components/ui/CertChainViewer'
import { cn } from '@/lib/utils'
import type { SessionDetail } from '@/api'

type Tab = 'overview' | 'timeline' | 'certificates' | 'shap'

export default function SessionDrilldownPage() {
  const { id = '', sessionId = '' } = useParams()
  const { data, isLoading, isError, error, refetch } = useSessionDetail(id, sessionId)
  const [tab, setTab] = useState<Tab>('overview')

  if (isLoading) return <LoadingState label="Loading session…" />
  if (isError) return <ErrorState message={(error as Error)?.message} onRetry={() => refetch()} />
  if (!data) return <ErrorState message="Session not found." onRetry={() => refetch()} />

  const tabs: Array<{ key: Tab; label: string; count?: number }> = [
    { key: 'overview', label: 'Handshake' },
    { key: 'timeline', label: 'Timeline', count: data.timeline.length },
    { key: 'certificates', label: 'Certificates', count: data.certChain.length },
    { key: 'shap', label: 'SHAP', count: data.shap.length },
  ]

  return (
    <div>
      <Link to={`/analyses/${id}`} className="text-[11px] text-base-400 hover:text-accent">← Back to analysis</Link>

      <div className="mb-3 mt-1 flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="flex items-center gap-2 text-lg font-bold text-base-50">
            <CodeBlock className="text-[13px]">{data.protocol}</CodeBlock>
            <span className="font-mono text-[12px] text-base-300">{data.fiveTuple}</span>
          </h1>
          <p className="text-[12px] text-base-400">
            {data.isStarttls ? 'STARTTLS-wrapped' : 'implicit-TLS port'} ·
            {data.tlsVersion ? ` negotiated ${data.tlsVersion} · ` : ' no TLS negotiated · '}
            <SeverityBadge severity={data.maxSeverity} />
          </p>
        </div>
        <ScoreGauge score={data.riskScore} size="md" />
      </div>

      {/* Tabs */}
      <div className="mb-3 flex gap-1 border-b border-base-600/60">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              '-mb-px border-b-2 px-3 py-2 text-[12px] font-semibold uppercase tracking-wide',
              tab === t.key
                ? 'border-accent text-accent'
                : 'border-transparent text-base-400 hover:text-base-200',
            )}
          >
            {t.label}
            {t.count != null && <span className="ml-1.5 rounded bg-base-700 px-1 text-[10px]">{t.count}</span>}
          </button>
        ))}
      </div>

      {tab === 'overview' && <HandshakeTab detail={data} />}
      {tab === 'timeline' && (
        <Panel title="Protocol timeline" subtitle="client & server byte offsets">
          <SessionTimeline events={data.timeline} />
        </Panel>
      )}
      {tab === 'certificates' && (
        <Panel title="Certificate chain analysis">
          <CertChainViewer chain={data.certChain} chainResult={data.chainResult} />
        </Panel>
      )}
      {tab === 'shap' && (
        <Panel
          title="ML risk explanation"
          subtitle={data.ruleMlAgreement === 'agrees' ? 'model agrees with rules engine' : `model ${data.ruleMlAgreement.replace('disagrees-', 'disagrees · ')}`}
        >
          <ExplanationPanel rows={data.shap} />
        </Panel>
      )}
    </div>
  )
}

function HandshakeTab({ detail }: { detail: SessionDetail }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Panel title="Negotiated parameters">
        <KeyValue k="TLS version" v={<CodeBlock>{detail.tlsVersion ?? '—'}</CodeBlock>} />
        <KeyValue k="Cipher suite" v={<CodeBlock>{detail.cipher ?? '—'}</CodeBlock>} />
        <KeyValue k="Cipher IANA" v={detail.cipherIana ? <CodeBlock>0x{detail.cipherIana}</CodeBlock> : '—'} />
        <KeyValue
          k="Bulk encryption"
          v={<span className="uppercase text-base-200">{detail.cipherKind ?? '—'}</span>}
        />
        <KeyValue
          k="Strength"
          v={
            detail.cipherStrength == null ? (
              '—'
            ) : (
              <span className={cn('font-mono', detail.cipherStrength >= 0.85 ? 'text-positive' : detail.cipherStrength >= 0.6 ? 'text-sev-medium' : 'text-sev-high')}>
                {detail.cipherStrength.toFixed(3)}
              </span>
            )
          }
        />
        <KeyValue
          k="Forward secrecy"
          v={
            detail.pfsSupported == null ? '—' : detail.pfsSupported ? <span className="text-positive">PFS supported</span> : <span className="text-sev-high">static key exchange</span>
          }
        />
        <KeyValue
          k="Certificate chain"
          v={
            <span className={detail.certChainValid ? 'text-positive' : 'text-sev-high'}>
              {detail.chainResult === 'no-cert' ? 'no certificate captured' : detail.chainResult}
            </span>
          }
        />
        <KeyValue
          k="ML / rules agreement"
          v={<span className="font-mono text-[11px] text-base-300">{detail.ruleMlAgreement}</span>}
        />
        <KeyValue
          k="Anomaly flag"
          v={
            detail.isAnomaly ? (
              <span className="text-sev-high">anomalous (isolation forest)</span>
            ) : (
              <span className="text-base-300">in fleet baseline</span>
            )
          }
        />
      </Panel>

      <Panel title="ClientHello">
        {detail.clientHello ? (
          <>
            <KeyValue k="SNI" v={detail.clientHello.sni ? <CodeBlock>{detail.clientHello.sni}</CodeBlock> : '—'} />
            <KeyValue
              k="Offered versions"
              v={<span className="font-mono text-[11px] text-base-200">{detail.clientHello.offeredVersions.join(', ') || '—'}</span>}
            />
            <KeyValue
              k="ALPN"
              v={<span className="font-mono text-[11px] text-base-200">{detail.clientHello.alpn.join(', ') || '—'}</span>}
            />
            <KeyValue
              k="Supported groups"
              v={<span className="font-mono text-[11px] text-base-300">{detail.clientHello.supportedGroups.map((g) => `0x${g.toString(16).padStart(4, '0')}`).join(', ') || '—'}</span>}
            />
            <div className="pt-1">
              <div className="mb-1 text-[11px] uppercase tracking-wider text-base-400">Offered cipher suites</div>
              <div className="scrollbar-thin flex max-h-40 flex-wrap gap-1 overflow-y-auto">
                {detail.clientHello.cipherSuites.map((cs) => (
                  <span key={cs} className="rounded bg-base-800 px-1.5 py-0.5 font-mono text-[10px] text-base-200">
                    {cs}
                  </span>
                ))}
              </div>
            </div>
          </>
        ) : (
          <p className="py-2 text-sm text-base-400">No ClientHello parsed for this session.</p>
        )}
      </Panel>

      <div className="lg:col-span-2">
        <Panel title="Session metadata" padded={false}>
          <div className="grid grid-cols-2 gap-x-6 p-3 sm:grid-cols-3 lg:grid-cols-5">
            <KeyValue k="Client" v={<CodeBlock>{detail.srcIp}:{detail.srcPort}</CodeBlock>} />
            <KeyValue k="Server" v={<CodeBlock>{detail.dstIp}:{detail.dstPort}</CodeBlock>} />
            <KeyValue k="STARTTLS" v={detail.isStarttls ? 'yes' : 'no'} />
            <KeyValue
              k="Transition offset"
              v={detail.transitionOffset != null ? <CodeBlock>0x{detail.transitionOffset.toString(16)}</CodeBlock> : '—'}
            />
            <KeyValue k="Transport" v="TCP" />
          </div>
        </Panel>
      </div>
    </div>
  )
}