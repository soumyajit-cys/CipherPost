/**
 * CipherPost API contract — typed interfaces shared by the real HTTP client
 * and the mock client. Swap backends without touching components.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type JobStatus = 'pending' | 'processing' | 'completed' | 'failed'
export type SeverityLabel = Severity | 'none'

export const SEVERITY_ORDER: Record<SeverityLabel, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0,
}

export interface AnalysisSummary {
  id: string
  filename: string
  status: JobStatus
  progress: number
  fileSize: number
  createdAt: string
  completedAt: string | null
  sessionsCount: number
  findingsCount: number
  postureScore: number | null
  maxSeverity: SeverityLabel | null
}

export interface Finding {
  id: number
  sessionId: string
  ruleId: string
  ruleName: string
  severity: Severity
  title: string
  description: string
  reference: string
  kind: 'rule' | 'ml' | 'anomaly'
  evidence: Record<string, unknown> | null
  session: { fiveTuple: string; protocol: string }
}

export interface SessionSummary {
  id: string
  protocol: string
  fiveTuple: string
  isStarttls: boolean
  tlsVersion: string | null
  cipher: string | null
  cipherStrength: number | null
  pfsSupported: boolean | null
  certChainValid: boolean | null
  riskScore: number | null
  isAnomaly: boolean
  maxSeverity: SeverityLabel
  findingCount: number
}

export interface ClientHelloDetail {
  sni: string | null
  alpn: string[]
  offeredVersions: string[]
  cipherSuites: string[]
  supportedGroups: number[]
}

export interface CertInfo {
  subject: string
  issuer: string
  notBefore: string | null
  notAfter: string | null
  daysValid: number | null
  daysRemaining: number | null
  pubkeyAlg: string
  pubkeyBits: number | null
  signatureAlg: string
  selfSigned: boolean
  isCa: boolean
  weakSignature: boolean
  shortKey: boolean
  expired: boolean
  notYetValid: boolean
  serial: string
  sans: string[]
  chainResult: string
}

export type TimelineEventType =
  | 'client-command'
  | 'plaintext-server'
  | 'starttls'
  | 'tls'
  | 'plaintext'

export interface TimelineEvent {
  offset: number
  direction: 'client' | 'server'
  type: TimelineEventType
  summary: string
  raw: string
}

export interface ShapRow {
  feature: string
  value: number | null
  impact: number
  method: string
}

export interface SessionDetail extends SessionSummary {
  srcIp: string
  dstIp: string
  srcPort: number
  dstPort: number
  transitionOffset: number | null
  cipherIana: string | null
  cipherKind: string | null
  chainResult: string
  chainError: string
  clientHello: ClientHelloDetail | null
  certChain: CertInfo[]
  timeline: TimelineEvent[]
  shap: ShapRow[]
  ruleMlAgreement: 'agrees' | 'disagrees-ml-more-severe' | 'disagrees-rules-more-severe'
}

export interface FleetSummary {
  totalSessions: number
  fleetScore: number
  anomalyCount: number
  severityDistribution: Partial<Record<SeverityLabel, number>>
  sessions: {
    fiveTuple: string
    protocol: string
    riskScore: number | null
    isAnomaly: boolean
    maxSeverity: SeverityLabel
    tlsVersion: string | null
  }[]
}

export interface AnalysisDetail {
  id: string
  filename: string
  status: JobStatus
  progress: number
  fileSize: number
  createdAt: string
  completedAt: string | null
  postureScore: number
  findingsCount: number
  sessionsCount: number
  maxSeverity: SeverityLabel
  summaries: SessionSummary[]
  sessions: SessionDetail[]
  findings: Finding[]
  fleet: FleetSummary
}

/** Cumulative fleet/drill data across all analyses (for the Fleet view). */
export interface FleetDrillData {
  analyses: {
    id: string
    filename: string
    createdAt: string
    postureScore: number
    maxSeverity: SeverityLabel
    sessionsCount: number
    findingsCount: number
    severityDistribution: Partial<Record<SeverityLabel, number>>
  }[]
  overall: {
    totalSessions: number
    avgPosture: number
    totalFindings: number
    anomalySessions: number
    severityDistribution: Partial<Record<SeverityLabel, number>>
  }
  topFindingTypes: { ruleId: string; ruleName: string; count: number; sessionsInvolved: number }[]
  postureTrend: { date: string; score: number }[]
}

export interface AnalysisSlice {
  analyses: AnalysisDetail[]
}

/** Upload progress callback. */
export interface UploadHandle {
  abort: () => void
}

export interface ApiClient {
  /** List all analyses (summaries). */
  listAnalyses(): Promise<AnalysisSummary[]>
  /** Full detail for one analysis (sessions + findings + fleet). */
  getAnalysis(id: string): Promise<AnalysisDetail>
  /** Drill-down for a single session within an analysis. */
  getSession(id: string, sessionId: string): Promise<SessionDetail | null>
  /** Fleet drill data across all analyses. */
  getFleetDrill(): Promise<FleetDrillData>
  /** Job status + progress for async uploads. */
  getJobStatus(id: string): Promise<AnalysisSummary>
  /** Upload a PCAP; returns job id and polling handle. */
  uploadPcap(file: File, onProgress?: (pct: number) => void): Promise<{ jobId: string }>
  /** Report download URL for a given format. */
  reportUrl(id: string, format: 'json' | 'html' | 'pdf'): string
}