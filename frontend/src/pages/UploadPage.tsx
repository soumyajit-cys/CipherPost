import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useJobStatus, useUpload } from '@/hooks/useApi'
import { CodeBlock } from '@/components/ui/primitives'
import { cn, formatBytes } from '@/lib/utils'
import { useQueryClient } from '@tanstack/react-query'
import { queryKeys } from '@/hooks/useApi'

const MAX_SIZE = 500 * 1024 * 1024

function validate(file: File): string | null {
  if (!/\.(pcap|pcapng)$/i.test(file.name)) return 'Only .pcap / .pcapng captures are accepted.'
  if (file.size > MAX_SIZE) return 'Capture exceeds the 500 MB upload limit.'
  if (file.size === 0) return 'Capture is empty.'
  return null
}

export default function UploadPage() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [video, setVideo] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const mutation = useUpload()

  const jobId = mutation.data?.jobId ?? null
  const jobStatus = useJobStatus(jobId ?? '', Boolean(jobId))
  const isRunning = jobId && (jobStatus.data?.status === 'processing' || jobStatus.data?.status === 'pending')

  useEffect(() => {
    if (jobStatus.isSuccess && jobStatus.data?.status === 'completed') {
      qc.invalidateQueries({ queryKey: queryKeys.analyses })
      qc.invalidateQueries({ queryKey: queryKeys.fleet })
      navigate(`/app/analyses/${jobStatus.data.id}`)
    }
  }, [jobStatus.isSuccess, jobStatus.data?.status, jobId, navigate, qc])

  const onFiles = (list: FileList | null) => {
    const f = list?.[0]
    setError(null)
    setVideo(null)
    if (!f) return
    const err = validate(f)
    if (err) { setError(err); setFile(null); return }
    setFile(f)
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) { setError('Select a capture file first.'); return }
    setError(null)
    mutation.mutate(file, {
      onError: (err) => setError((err as Error)?.message ?? 'Upload failed'),
    })
  }

  return (
    <div>
      <h1 className="text-lg font-bold text-base-50">New Analysis</h1>
      <p className="mb-4 text-[12px] text-base-400">
        Upload a SMTP / IMAP / POP3 packet capture. The job runs asynchronously and reports
        posture in the dashboard when it completes.
      </p>

      {video && (
        <div className="mb-4 rounded border border-accent/40 bg-accent/10 px-3 py-2 text-[12px] text-accent">
          {video}
        </div>
      )}

      <form onSubmit={submit} className="rounded-md border border-base-600/60 bg-base-850">
        {!file ? (
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); onFiles(e.dataTransfer.files) }}
            onClick={() => inputRef.current?.click()}
            className={cn(
              'flex cursor-pointer flex-col items-center justify-center gap-2 border-2 border-dashed px-6 py-16 text-center transition-colors',
              dragOver ? 'border-accent bg-accent/5' : 'border-base-600 hover:border-base-500',
            )}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".pcap,.pcapng"
              className="hidden"
              onChange={(e) => onFiles(e.target.files)}
            />
            <span className="text-2xl">⇧</span>
            <p className="text-sm font-medium text-base-200">
              Drop a capture here, or click to browse
            </p>
            <p className="text-[11px] text-base-400">
              .pcap / .pcapng · up to 500 MB · SMTP, IMAP or POP3
            </p>
          </div>
        ) : (
          <div className="flex items-center gap-3 border-b border-base-600/60 px-4 py-3">
            <span className="h-2.5 w-2.5 rounded-full bg-positive" />
            <div className="min-w-0 flex-1">
              <div className="truncate font-medium text-base-100">{file.name}</div>
              <CodeBlock className="text-[11px] text-base-400">{formatBytes(file.size)}</CodeBlock>
            </div>
            <button type="button" onClick={() => setFile(null)} className="text-[12px] text-base-400 hover:text-base-200">
              Remove
            </button>
          </div>
        )}

        <div className="flex items-center justify-between gap-3 px-4 py-3">
          {error ? (
            <span className="text-[12px] font-medium text-sev-critical">{error}</span>
          ) : (
            <span className="text-[12px] text-base-400">
              Captures are analyzed locally; findings are deterministic-rule backed with ML risk scoring.
            </span>
          )}
          <button
            type="submit"
            disabled={!file || mutation.isPending}
            className={cn(
              'rounded border px-4 py-1.5 text-[13px] font-semibold',
              (!file || mutation.isPending)
                ? 'cursor-not-allowed border-base-600 text-base-400'
                : 'border-accent/60 bg-accent/10 text-accent hover:bg-accent/20',
            )}
          >
            {mutation.isPending ? 'Submitting…' : 'Analyze'}
          </button>
        </div>
      </form>

      {jobId && isRunning && (
        <div className="mt-4 rounded-md border border-base-600/60 bg-base-850 p-4">
          <div className="mb-2 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-accent" />
              <span className="text-sm font-medium text-base-100">
                {jobStatus.data?.status === 'processing' ? 'Analyzing capture…' : 'Queued…'}
              </span>
            </div>
            <CodeBlock className="text-[11px] text-base-400">job {jobId}</CodeBlock>
          </div>
          <div className="h-2 overflow-hidden rounded-sm bg-base-800">
            <div
              className="h-full bg-accent transition-all duration-700"
              style={{ width: `${Math.round((jobStatus.data?.progress ?? 0) * 100)}%` }}
            />
          </div>
          <div className="mt-1 flex justify-between text-[11px] text-base-400">
            <span>{Math.round((jobStatus.data?.progress ?? 0) * 100)}%</span>
            <span>reassembly → TLS parsing → rules → ML scoring</span>
          </div>
        </div>
      )}

      <div className="mt-6">
        <h2 className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-base-400">
          Pipeline stages
        </h2>
        <ol className="space-y-1 font-mono text-[12px] text-base-300">
          <li>1 · TCP stream reassembly &amp; protocol classification (SYN-anchored)</li>
          <li>2 · TLS record + handshake parsing (ClientHello / ServerHello / Certificate)</li>
          <li>3 · X.509 chain validation + 19 deterministic rules (NIST / OWASP)</li>
          <li>4 · ML risk score (gradient boost) + isolation-forest anomaly + SHAP</li>
          <li>5 · JSON / HTML / PDF report generation</li>
        </ol>
      </div>
    </div>
  )
}