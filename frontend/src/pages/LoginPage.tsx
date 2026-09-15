import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { api, API_MODE } from '@/api'
import { Panel } from '@/components/ui/State'

export default function LoginPage() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('admin@cipherpost.local')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await api.login(email, password)
      navigate('/app', { replace: true })
    } catch (err) {
      setError((err as Error)?.message === 'UNAUTHORIZED'
        ? 'Invalid email or password.'
        : (err as Error)?.message ?? 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto flex min-h-[70vh] max-w-md flex-col justify-center px-4">
      <div className="mb-6 text-center">
        <div className="text-lg font-bold tracking-tight text-base-50">
          Cipher<span className="text-accent">Post</span>
        </div>
        <p className="mt-1 text-xs text-base-400">
          {API_MODE === 'mock' ? 'Fixture mode — any credentials work.' : 'Sign in to the console.'}
        </p>
      </div>
      <Panel title="Sign in">
        <form onSubmit={submit} className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-base-400">Email</span>
            <input
              type="email" value={email} onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded border border-base-600 bg-base-900 px-3 py-2 text-sm text-base-100"
              autoComplete="username"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-base-400">Password</span>
            <input
              type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded border border-base-600 bg-base-900 px-3 py-2 text-sm text-base-100"
              autoComplete="current-password"
            />
          </label>
          {error && (
            <div className="rounded border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
              {error}
            </div>
          )}
          <button
            type="submit" disabled={busy}
            className="w-full rounded bg-accent px-3 py-2 text-sm font-semibold text-base-950 hover:bg-accent/90 disabled:opacity-50"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </Panel>
      <p className="mt-4 text-center text-xs text-base-500">
        Default bootstrap admin is <span className="font-mono">admin@cipherpost.local</span> —{' '}
        <Link to="/" className="text-accent hover:underline">back to site</Link>
      </p>
    </div>
  )
}
