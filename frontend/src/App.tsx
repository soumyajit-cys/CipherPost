import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AppShell } from '@/components/layout/AppShell'
import AnalysisListPage from '@/pages/AnalysisListPage'
import UploadPage from '@/pages/UploadPage'
import AnalysisDetailPage from '@/pages/AnalysisDetailPage'
import SessionDrilldownPage from '@/pages/SessionDrilldownPage'
import FleetOverviewPage from '@/pages/FleetOverviewPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      refetchOnWindowFocus: false,
      staleTime: 10_000,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppShell>
          <Routes>
            <Route path="/" element={<AnalysisListPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/analyses/:id" element={<AnalysisDetailPage />} />
            <Route path="/analyses/:id/sessions/:sessionId" element={<SessionDrilldownPage />} />
            <Route path="/fleet" element={<FleetOverviewPage />} />
            <Route path="*" element={<AnalysisListPage />} />
          </Routes>
        </AppShell>
      </BrowserRouter>
    </QueryClientProvider>
  )
}