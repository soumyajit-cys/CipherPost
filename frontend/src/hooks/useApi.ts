import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api'

export const queryKeys = {
  analyses: ['analyses'] as const,
  analysis: (id: string) => ['analysis', id] as const,
  session: (id: string, sessionId: string) => ['session', id, sessionId] as const,
  fleet: ['fleet'] as const,
  job: (id: string) => ['job', id] as const,
}

/** List of all analyses (history view + header polling trigger). */
export function useAnalyses() {
  return useQuery({
    queryKey: queryKeys.analyses,
    queryFn: () => api.listAnalyses(),
    staleTime: 15_000,
    refetchInterval: (q) =>
      q.state.data?.some((a) => a.status === 'processing' || a.status === 'pending') ? 2000 : false,
  })
}

/** Full analysis detail. */
export function useAnalysisDetail(id: string, opts?: { refetchInterval?: number | false }) {
  return useQuery({
    queryKey: queryKeys.analysis(id),
    queryFn: () => api.getAnalysis(id),
    enabled: Boolean(id),
    refetchInterval: opts?.refetchInterval ?? false,
  })
}

/** Session drill-down. */
export function useSessionDetail(id: string, sessionId: string | null) {
  return useQuery({
    queryKey: queryKeys.session(id ?? '', sessionId ?? ''),
    queryFn: () => (id && sessionId ? api.getSession(id, sessionId) : null),
    enabled: Boolean(id && sessionId),
  })
}

/** Fleet drill data across the whole corpus. */
export function useFleetDrill() {
  return useQuery({
    queryKey: queryKeys.fleet,
    queryFn: () => api.getFleetDrill(),
    staleTime: 30_000,
  })
}

/** Job status polling. */
export function useJobStatus(jobId: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.job(jobId),
    queryFn: () => api.getJobStatus(jobId),
    enabled,
    refetchInterval: (q) => {
      const s = q.state.data?.status
      if (s === 'completed' || s === 'failed') return false
      if (enabled) return 1500
      return false
    },
  })
}

/** Upload a PCAP and await completion. Invalidates the analyses list on success. */
export function useUpload() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (file: File) => api.uploadPcap(file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.analyses })
    },
  })
}