import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AppShell } from '@/components/layout/AppShell'
import AnalysisListPage from '@/pages/AnalysisListPage'
import UploadPage from '@/pages/UploadPage'
import AnalysisDetailPage from '@/pages/AnalysisDetailPage'
import SessionDrilldownPage from '@/pages/SessionDrilldownPage'
import FleetOverviewPage from '@/pages/FleetOverviewPage'
import LivePage from '@/pages/LivePage'
import LandingPage from '@/pages/LandingPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      refetchOnWindowFocus: false,
      staleTime: 10_000,
    },
  },
})

function DashboardRoutes() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<AnalysisListPage />} />
        <Route path="/live" element={<LivePage />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/fleet" element={<FleetOverviewPage />} />
        <Route path="/analyses/:id" element={<AnalysisDetailPage />} />
        <Route path="/analyses/:id/sessions/:sessionId" element={<SessionDrilldownPage />} />
        <Route path="*" element={<AnalysisListPage />} />
      </Routes>
    </AppShell>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          {/* Public marketing — standalone deployable at / */}
          <Route path="/" element={<LandingPage />} />
          {/* Dashboard family — coherent tokens, live motion */}
          <Route path="/app/*" element={<DashboardRoutes />} />
          {/* Back-compat redirects for old dashboard links */}
          <Route path="/live" element={<Navigate to="/app/live" replace />} />
          <Route path="/upload" element={<Navigate to="/app/upload" replace />} />
          <Route path="/fleet" element={<Navigate to="/app/fleet" replace />} />
          <Route path="/analyses/:id" element={<Navigate to="/app/analyses/:id" replace />} />
          <Route path="/analyses/:id/sessions/:sessionId" element={<Navigate to="/app/analyses/:id/sessions/:sessionId" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}