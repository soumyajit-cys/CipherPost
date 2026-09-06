/**
 * Mock API client — serves the real pipeline's exported fixture data
 * (see scripts/export_mock_data.py). Implements the same ApiClient
 * contract so switching to the live backend is a one-line change
 * (see src/api/index.ts).
 */
import type {
  AnalysisDetail,
  AnalysisSlice,
  AnalysisSummary,
  ApiClient,
  FleetDrillData,
  SessionDetail,
} from '../types'
import { SEVERITY_ORDER } from '../types'
import slice from './data.json'

const ANON = slice as AnalysisSlice
const BY_ID = new Map(ANON.analyses.map((a) => [a.id, a]))
// A fresh analysis id inserted for upload simulation.
let UPLOADED: AnalysisDetail | null = null

const analysisToSummary = (a: AnalysisDetail): AnalysisSummary => ({
  id: a.id,
  filename: a.filename,
  status: a.status,
  progress: a.progress,
  fileSize: a.fileSize,
  createdAt: a.createdAt,
  completedAt: a.completedAt,
  sessionsCount: a.sessionsCount,
  findingsCount: a.findingsCount,
  postureScore: a.postureScore,
  maxSeverity: a.maxSeverity,
})

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))

const simulateLatency = async () => {
  await wait(90 + Math.random() * 200)
}

export const mockClient: ApiClient = {
  async listAnalyses(): Promise<AnalysisSummary[]> {
    await simulateLatency()
    const all = [UPLOADED, ...ANON.analyses].filter(Boolean) as AnalysisDetail[]
    return all.map(analysisToSummary).sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  },

  async getAnalysis(id: string): Promise<AnalysisDetail> {
    await simulateLatency()
    const a = BY_ID.get(id) ?? UPLOADED
    if (!a) throw new Error(`analysis ${id} not found`)
    if (UPLOADED && UPLOADED.id === id) return UPLOADED
    return a
  },

  async getSession(id: string, sessionId: string): Promise<SessionDetail | null> {
    await simulateLatency()
    const a = await this.getAnalysis(id)
    return a.sessions.find((s) => s.id === sessionId) ?? null
  },

  async getFleetDrill(): Promise<FleetDrillData> {
    await simulateLatency()
    const analyses = ([UPLOADED, ...ANON.analyses].filter(Boolean) as AnalysisDetail[])
      .filter((a) => a.status === 'completed')

    const overallSev: FleetDrillData['overall']['severityDistribution'] = {}
    let totalSessions = 0
    let anomalySessions = 0
    let totalFindings = 0
    const findingsByRule = new Map<string, { ruleId: string; ruleName: string; sessions: Set<string> }>()

    for (const a of analyses) {
      totalSessions += a.sessionsCount
      anomalySessions += a.fleet.anomalyCount
      totalFindings += a.findings.length
      for (const [sev, n] of Object.entries(a.fleet.severityDistribution)) {
        overallSev[sev as keyof typeof overallSev] = (overallSev[sev as keyof typeof overallSev] ?? 0) + (n as number)
      }
      for (const f of a.findings) {
        const cur = findingsByRule.get(f.ruleId) ?? { ruleId: f.ruleId, ruleName: f.ruleName, sessions: new Set<string>() }
        cur.sessions.add(`${a.id}/${f.sessionId}`)
        findingsByRule.set(f.ruleId, cur)
      }
    }

    const completed = analyses.filter((a) => a.postureScore != null)
    const avgPosture = completed.length
      ? Math.round(completed.reduce((s, a) => s + (a.postureScore ?? 0), 0) / completed.length)
      : 0

    return {
      analyses: analyses
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .map((a) => ({
          id: a.id,
          filename: a.filename,
          createdAt: a.createdAt,
          postureScore: a.postureScore,
          maxSeverity: a.maxSeverity,
          sessionsCount: a.sessionsCount,
          findingsCount: a.findingsCount,
          severityDistribution: a.fleet.severityDistribution,
        })),
      overall: {
        totalSessions,
        avgPosture,
        totalFindings,
        anomalySessions,
        severityDistribution: overallSev,
      },
      topFindingTypes: [...findingsByRule.values()]
        .map((v) => ({ ruleId: v.ruleId, ruleName: v.ruleName, count: v.sessions.size, sessionsInvolved: v.sessions.size }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 12),
      postureTrend: completed
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
        .map((a) => ({ date: a.createdAt, score: a.postureScore })),
    }
  },

  async getJobStatus(id: string): Promise<AnalysisSummary> {
    await simulateLatency()
    if (UPLOADED && UPLOADED.id === id) return analysisToSummary(UPLOADED)
    const a = BY_ID.get(id)
    if (!a) throw new Error(`job ${id} not found`)
    return analysisToSummary(a)
  },

  async uploadPcap(): Promise<{ jobId: string }> {
    await wait(250)
    // Simulate a job that completes after a few seconds of "processing".
    if (UPLOADED) return { jobId: UPLOADED.id }
    const src = BY_ID.get('pop3_tls12_nonpfs') ?? ANON.analyses[0]
    const clone: AnalysisDetail = JSON.parse(JSON.stringify(src))
    clone.id = 'mock-upload-' + Math.random().toString(36).slice(2, 10)
    clone.filename = 'upload.pcap'
    clone.status = 'pending'
    clone.progress = 0
    clone.createdAt = new Date().toISOString()
    clone.completedAt = null
    clone.postureScore = 0
    UPLOADED = clone
    // simulate async completion
    setTimeout(() => {
      if (!UPLOADED) return
      UPLOADED.status = 'processing'
      UPLOADED.progress = 0.45
    }, 700)
    setTimeout(() => {
      if (!UPLOADED) return
      UPLOADED.status = 'completed'
      UPLOADED.progress = 1
      UPLOADED.completedAt = new Date().toISOString()
      UPLOADED.postureScore = src.postureScore
    }, 2600)
    return { jobId: clone.id }
  },

  reportUrl(id: string, format: 'json' | 'html' | 'pdf'): string {
    return `/api/v1/jobs/${id}/report.${format}`
  },
}

export interface FleetShape {
  totalSessions: number
  fleetScore: number
  anomalyCount: number
  severityDistribution: Partial<Record<string, number>>
}
export type { SEVERITY_ORDER }