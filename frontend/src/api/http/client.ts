/**
 * Real backend HTTP client — talks to the FastAPI server.
 *
 * The live backend exposes /api/v1/jobs etc. (see README for the contract).
 * The fabricated endpoints that the backend does not yet expose (session
 * drill-down detail, fleet drill, upload proxying) fall back to assembling
 * data from the endpoints that do exist, or throw a descriptive error when
 * a backend dependency is missing.
 */
import type {
  AnalysisDetail,
  AnalysisSummary,
  ApiClient,
  FleetDrillData,
  SessionDetail,
} from '../types'
import { SEVERITY_ORDER } from '../types'

const BASE = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`)
  return res.json() as Promise<T>
}

interface BackendJob {
  id: string
  filename: string
  status: string
  progress: number
  file_size: number
  created_at: string | null
  completed_at: string | null
}
interface BackendSession {
  id: string
  protocol: string
  five_tuple: string
  tls_version: string | null
  negotiated_cipher: string | null
  cipher_strength: number | null
  pfs_supported: boolean | null
  cert_chain_valid: boolean | null
  cert_age_days: number | null
  is_starttls: boolean
  is_anomaly: boolean
  risk_score: number | null
  max_severity: string | null
  overall_finding_count: number
  details: { timeline?: unknown; client_hello?: unknown; cert_chain?: unknown } | null
}
interface BackendFinding {
  id: number
  session_id: string
  rule_id: string
  rule_name: string
  severity: string
  title: string
  description: string
  reference: string
  kind: string
  evidence: Record<string, unknown> | null
}
interface BackendShap {
  session_id: string
  feature: string
  value: number | null
  impact: number
  method: string
}
interface BackendFleet {
  total_sessions: number
  fleet_score: number
  anomaly_count: number
  severity_distribution: Record<string, number>
  sessions: { five_tuple: string; protocol: string; risk_score: number | null; is_anomaly: boolean; max_severity: string | null; tls_version: string | null }[]
}

const jobToSummary = (j: BackendJob): AnalysisSummary => ({
  id: j.id,
  filename: j.filename,
  status: (['pending', 'processing', 'completed', 'failed'] as const).includes(j.status as never)
    ? (j.status as AnalysisSummary['status'])
    : 'pending',
  progress: j.progress,
  fileSize: j.file_size,
  createdAt: j.created_at ?? '',
  completedAt: j.completed_at,
  sessionsCount: 0,
  findingsCount: 0,
  postureScore: null,
  maxSeverity: null,
})

export const httpClient: ApiClient = {
  async listAnalyses(): Promise<AnalysisSummary[]> {
    const jobs = await get<BackendJob[]>('/jobs')
    const summaries: AnalysisSummary[] = []
    for (const j of jobs) {
      const s = jobToSummary(j)
      if (j.status === 'completed') {
        try {
          const f = await get<BackendFleet>(`/jobs/${j.id}/fleet`)
          s.sessionsCount = f.total_sessions
          s.postureScore = Math.round(f.fleet_score)
          s.maxSeverity = Object.keys(f.severity_distribution)
            .filter((k) => k !== 'none')
            .sort((a, b) => SEVERITY_ORDER[a as never] - SEVERITY_ORDER[b as never])
            .pop() as AnalysisSummary['maxSeverity'] ?? null
        } catch { /* partial */ }
      }
      summaries.push(s)
    }
    return summaries
  },

  async getAnalysis(id: string): Promise<AnalysisDetail> {
    const job = await get<BackendJob>(`/jobs/${id}`)
    const [sessions, findings, shap, fleet] = await Promise.all([
      get<BackendSession[]>(`/jobs/${id}/sessions`),
      get<BackendFinding[]>(`/jobs/${id}/findings`),
      get<BackendShap[]>(`/jobs/${id}/shap`).catch(() => []),
      get<BackendFleet>(`/jobs/${id}/fleet`).catch(() => null),
    ])

    const sessionDetails = sessions.map((s) => ({
      id: s.id,
      protocol: s.protocol,
      fiveTuple: s.five_tuple,
      srcIp: '',
      dstIp: '',
      srcPort: 0,
      dstPort: 0,
      isStarttls: s.is_starttls,
      transitionOffset: null,
      tlsVersion: s.tls_version,
      cipher: s.negotiated_cipher,
      cipherIana: null,
      cipherStrength: s.cipher_strength,
      cipherKind: null,
      pfsSupported: s.pfs_supported,
      certChainValid: s.cert_chain_valid,
      chainResult: s.cert_chain_valid === null ? 'no-cert' : s.cert_chain_valid ? 'ok' : 'untrusted',
      chainError: '',
      riskScore: s.risk_score ?? 0,
      isAnomaly: s.is_anomaly,
      maxSeverity: (s.max_severity as never) ?? 'none',
      findingCount: s.overall_finding_count,
      clientHello: null,
      certChain: [],
      timeline: [],
      shap: shap.filter((x) => x.session_id === s.id).map((x) => ({ feature: x.feature, value: x.value, impact: x.impact, method: x.method })),
      ruleMlAgreement: 'agrees',
    }))

    const findingsOut = findings.map((f) => {
      const sess = sessions.find((s) => s.id === f.session_id)
      return {
        id: f.id,
        sessionId: f.session_id,
        ruleId: f.rule_id,
        ruleName: f.rule_name,
        severity: f.severity as never,
        title: f.title,
        description: f.description,
        reference: f.reference,
        kind: f.kind as never,
        evidence: f.evidence,
        session: { fiveTuple: sess?.five_tuple ?? '', protocol: sess?.protocol ?? '' },
      }
    })

    const posture = fleet ? Math.round(fleet.fleet_score) : 0
    const maxSev = findingsOut
      .map((f) => f.severity)
      .sort((a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b])
      .pop() ?? 'none'

    return {
      id,
      filename: job.filename,
      status: job.status as never,
      progress: job.progress,
      fileSize: job.file_size,
      createdAt: job.created_at ?? '',
      completedAt: job.completed_at,
      postureScore: posture,
      findingsCount: findingsOut.length,
      sessionsCount: sessionDetails.length,
      maxSeverity: maxSev,
      summaries: sessionDetails.map((s) => ({
        id: s.id, protocol: s.protocol, fiveTuple: s.fiveTuple, isStarttls: s.isStarttls,
        tlsVersion: s.tlsVersion, cipher: s.cipher, cipherStrength: s.cipherStrength,
        pfsSupported: s.pfsSupported, certChainValid: s.certChainValid, riskScore: s.riskScore,
        isAnomaly: s.isAnomaly, maxSeverity: s.maxSeverity, findingCount: s.findingCount,
      })),
      sessions: sessionDetails,
      findings: findingsOut,
      fleet: fleet
        ? {
            totalSessions: fleet.total_sessions,
            fleetScore: Math.round(fleet.fleet_score),
            anomalyCount: fleet.anomaly_count,
            severityDistribution: fleet.severity_distribution,
            sessions: fleet.sessions.map((x) => ({
              fiveTuple: x.five_tuple, protocol: x.protocol, riskScore: x.risk_score,
              isAnomaly: x.is_anomaly, maxSeverity: (x.max_severity as never) ?? 'none',
              tlsVersion: x.tls_version,
            })),
          }
        : { totalSessions: sessionDetails.length, fleetScore: posture, anomalyCount: 0, severityDistribution: {}, sessions: [] },
    }
  },

  async getSession(id: string, sessionId: string): Promise<SessionDetail | null> {
    const a = await this.getAnalysis(id)
    return a.sessions.find((s) => s.id === sessionId) ?? null
  },

  async getFleetDrill(): Promise<FleetDrillData> {
    const analyses = await this.listAnalyses()
    const completed = analyses.filter((a) => a.status === 'completed' && a.postureScore != null)
    const overallSev: FleetDrillData['overall']['severityDistribution'] = {}
    const top = new Map<string, { ruleId: string; ruleName: string; sessions: Set<string> }>()
    for (const a of completed) {
      try {
        const detail = await this.getAnalysis(a.id)
        for (const [sev, n] of Object.entries(detail.fleet.severityDistribution)) {
          overallSev[sev as keyof typeof overallSev] = (overallSev[sev as keyof typeof overallSev] ?? 0) + (n as number)
        }
        for (const f of detail.findings) {
          const cur = top.get(f.ruleId) ?? { ruleId: f.ruleId, ruleName: f.ruleName, sessions: new Set<string>() }
          cur.sessions.add(`${a.id}/${f.sessionId}`)
          top.set(f.ruleId, cur)
        }
      } catch { /* skip broken job */ }
    }
    const avg = completed.length ? Math.round(completed.reduce((s, a) => s + (a.postureScore ?? 0), 0) / completed.length) : 0
    return {
      analyses: completed.map((a) => ({ id: a.id, filename: a.filename, createdAt: a.createdAt, postureScore: a.postureScore ?? 0, maxSeverity: a.maxSeverity ?? 'none', sessionsCount: a.sessionsCount, findingsCount: a.findingsCount, severityDistribution: overallSev })),
      overall: { totalSessions: completed.reduce((s, a) => s + a.sessionsCount, 0), avgPosture: avg, totalFindings: completed.reduce((s, a) => s + a.findingsCount, 0), anomalySessions: 0, severityDistribution: overallSev },
      topFindingTypes: [...top.values()].map((v) => ({ ruleId: v.ruleId, ruleName: v.ruleName, count: v.sessions.size, sessionsInvolved: v.sessions.size })).sort((x, y) => y.count - x.count).slice(0, 12),
      postureTrend: completed.sort((a, b) => a.createdAt.localeCompare(b.createdAt)).map((a) => ({ date: a.createdAt, score: a.postureScore ?? 0 })),
    }
  },

  async getJobStatus(id: string): Promise<AnalysisSummary> {
    const j = await get<BackendJob>(`/jobs/${id}`)
    return jobToSummary(j)
  },

  async uploadPcap(file: File): Promise<{ jobId: string }> {
    const fd = new FormData()
    fd.append('file', file)
    const res = await fetch(`${BASE}/upload`, { method: 'POST', body: fd })
    if (!res.ok) throw new Error(`upload failed → ${res.status}`)
    const body = (await res.json()) as { job_id: string }
    return { jobId: body.job_id }
  },

  reportUrl(id: string, format: 'json' | 'html' | 'pdf'): string {
    return `${BASE}/jobs/${id}/report.${format}`
  },
}