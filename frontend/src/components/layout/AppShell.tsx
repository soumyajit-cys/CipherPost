import React, { useEffect, useState } from 'react'
import { Link, NavLink, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { API_MODE } from '@/api'

const NAV = [
  { to: '/app', label: 'Analyses', end: true },
  { to: '/app/live', label: 'Live', end: false },
  { to: '/app/upload', label: 'New Analysis', end: false },
  { to: '/app/fleet', label: 'Fleet', end: false },
]

function LiveIndicator() {
  const [status, setStatus] = useState<'streaming' | 'disconnected' | 'mock'>('mock')
  useEffect(() => {
    if (API_MODE === 'mock') {
      setStatus('mock')
      return
    }
    let cancelled = false
    let es: EventSource | null = null
    const base = (import.meta as any).env?.VITE_API_BASE_URL ?? '/api/v1'
    try {
      es = new EventSource(`${base}/live/stream`)
      es.onopen = () => !cancelled && setStatus('streaming')
      es.onerror = () => !cancelled && setStatus('disconnected')
    } catch {
      setStatus('disconnected')
    }
    // fallback poll for queue depth heartbeat
    const id = setInterval(async () => {
      if (cancelled) return
      try {
        const r = await fetch(`${base}/live/status`)
        if (r.ok && !cancelled) setStatus('streaming')
      } catch {
        if (!cancelled) setStatus('disconnected')
      }
    }, 8000)
    return () => {
      cancelled = true
      clearInterval(id)
      es?.close()
    }
  }, [])
  if (status === 'mock') {
    return (
      <span className="hidden items-center gap-1.5 rounded border border-base-600/60 px-2 py-0.5 text-[10px] uppercase tracking-wider text-base-400 sm:flex">
        <span className="h-1.5 w-1.5 rounded-full bg-sev-medium" /> fixture data
      </span>
    )
  }
  const isLive = status === 'streaming'
  return (
    <span
      className={cn(
        'hidden items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] uppercase tracking-wider sm:flex',
        isLive ? 'border-positive/30 bg-positive/10 text-positive' : 'border-sev-critical/30 bg-sev-critical/10 text-sev-critical',
      )}
      title={isLive ? 'Live stream connected — data is current' : 'Live stream disconnected — reconnecting'}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', isLive ? 'bg-positive animate-pulse' : 'bg-sev-critical')} />
      {isLive ? 'Streaming' : 'Disconnected'}
    </span>
  )
}

function useTheme() {
  const [dark, setDark] = useState(() => {
    const stored = localStorage.getItem('cipherpost-theme')
    if (stored) return stored === 'dark'
    return document.documentElement.classList.contains('dark')
  })
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    localStorage.setItem('cipherpost-theme', dark ? 'dark' : 'light')
  }, [dark])
  return { dark, toggle: () => setDark((d) => !d) }
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { dark, toggle } = useTheme()
  const location = useLocation()
  const isApp = location.pathname.startsWith('/app')

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-base-600/60 bg-base-900/95 backdrop-blur">
        <div className="mx-auto flex h-12 max-w-[1500px] items-center justify-between gap-4 px-4">
          <div className="flex items-center gap-6">
            <Link to="/" className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center rounded border border-accent/50 bg-accent/10">
                <span className="h-3 w-3 rounded-sm border-2 border-accent/70" />
              </span>
              <span className="text-sm font-bold tracking-tight text-base-50">
                Cipher<span className="text-accent">Post</span>
              </span>
            </Link>
            {isApp && (
              <nav className="flex items-center gap-1">
                {NAV.map((n) => (
                  <NavLink
                    key={n.to}
                    to={n.to}
                    end={n.end}
                    className={({ isActive }) =>
                      cn(
                        'rounded px-2.5 py-1 text-[13px] font-medium transition-colors',
                        isActive
                          ? 'bg-base-700 text-base-50'
                          : 'text-base-400 hover:bg-base-800 hover:text-base-200',
                      )
                    }
                  >
                    {n.label}
                  </NavLink>
                ))}
              </nav>
            )}
            {!isApp && (
              <Link to="/app" className="hidden text-[13px] font-medium text-base-400 hover:text-base-200 md:inline">
                ← Back to dashboard
              </Link>
            )}
          </div>

          <div className="flex items-center gap-3">
            {isApp ? <LiveIndicator /> : (
              <Link to="/app/live" className="hidden items-center gap-1.5 rounded bg-accent px-2.5 py-1 text-[12px] font-semibold text-base-950 hover:bg-accent/90 sm:inline-flex">
                View live
              </Link>
            )}
            <button
              onClick={toggle}
              aria-label="toggle theme"
              className="rounded border border-base-600/60 px-2 py-1 text-[13px] text-base-300 hover:bg-base-800"
            >
              {dark ? '☀' : '☾'}
            </button>
          </div>
        </div>
      </header>

      <main className={cn('mx-auto max-w-[1500px] px-4 pb-14 pt-4', location.pathname === '/app/upload' && 'max-w-3xl')}>
        {children}
      </main>

      <footer className="mx-auto max-w-[1500px] px-4 pb-6 text-[11px] text-base-500">
        CipherPost · deterministic rules-backed crypto posture (NIST SP 800-52r2 / OWASP), augmented by an
        explainable ML risk score (SHAP). Severity colors reflect finding criticality only.
      </footer>
    </div>
  )
}