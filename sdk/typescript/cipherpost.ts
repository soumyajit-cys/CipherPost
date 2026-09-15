/**
 * CipherPost TypeScript SDK (track 4) — typed fetch client over /api/v1.
 * Field names mirror the OpenAPI schema (snake_case on the wire).
 * Auth: `login()` stores a JWT, or pass `apiKey` for X-API-Key auth.
 */

export interface AuthUser {
  id: string;
  email: string;
  role: 'admin' | 'analyst' | 'auditor';
  org_id: string;
}

export interface Job { id: string; filename: string; status: string; progress: number; file_size: number; created_at: string | null; completed_at: string | null }
export interface Session { id: string; protocol: string; five_tuple: string; risk_score: number | null; max_severity: string | null; is_anomaly: boolean }
export interface Finding { id: number; session_id: string; rule_id: string; severity: string; title: string; description: string; compliance?: unknown[] | null }

export class CipherPostError extends Error {
  status: number;
  constructor(status: number, body: string) {
    super(`cipherpost api error ${status}: ${body.slice(0, 300)}`);
    this.status = status;
  }
}

export class CipherPostClient {
  private base: string;
  private token: string | null;
  private apiKey: string | null;

  constructor(opts: { baseUrl?: string; token?: string | null; apiKey?: string | null } = {}) {
    this.base = (opts.baseUrl ?? 'http://localhost:8000').replace(/\/$/, '');
    this.token = opts.token ?? null;
    this.apiKey = opts.apiKey ?? null;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    const h: Record<string, string> = { ...extra };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    if (this.apiKey) h['X-API-Key'] = this.apiKey;
    return h;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.base + path, {
      method,
      headers: { 'Content-Type': 'application/json', ...this.headers() },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) throw new CipherPostError(res.status, await res.text());
    return (await res.json()) as T;
  }

  private get<T>(path: string, params: Record<string, string | number | undefined> = {}): Promise<T> {
    const qs = Object.entries(params)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join('&');
    return this.req<T>('GET', qs ? `${path}?${qs}` : path);
  }

  async login(email: string, password: string): Promise<{ token: string; user: AuthUser }> {
    const out = await this.req<{ token: string; user: AuthUser }>('POST', '/api/v1/auth/login', { email, password });
    this.token = out.token;
    return out;
  }

  me = (): Promise<AuthUser> => this.get('/api/v1/auth/me');
  listJobs = (limit = 50): Promise<Job[]> => this.get('/api/v1/jobs', { limit });
  getJob = (id: string): Promise<Job> => this.get(`/api/v1/jobs/${id}`);
  jobSessions = (id: string): Promise<Session[]> => this.get(`/api/v1/jobs/${id}/sessions`);
  jobFindings = (id: string, severity?: string): Promise<Finding[]> => this.get(`/api/v1/jobs/${id}/findings`, { severity });
  jobFleet = (id: string): Promise<unknown> => this.get(`/api/v1/jobs/${id}/fleet`);
  sessions = (params: { protocol?: string; severity?: string; limit?: number } = {}): Promise<Session[]> => this.get('/api/v1/sessions', params);
  findings = (severity?: string): Promise<Finding[]> => this.get('/api/v1/findings', { severity });
  fleetTrend = (days = 7): Promise<unknown> => this.get('/api/v1/fleet/trend', { days });
  liveStatus = (): Promise<unknown> => this.get('/api/v1/live/status');
  agents = (): Promise<unknown> => this.get('/api/v1/agents');
  alerts = (limit = 50): Promise<unknown[]> => this.get('/api/v1/alerts', { limit });
  certsExpiring = (days = 30): Promise<unknown[]> => this.get('/api/v1/certs/expiring', { days });
  complianceSummary = (framework?: string): Promise<unknown> => this.get('/api/v1/compliance/summary', { framework });
  audit = (limit = 100): Promise<unknown[]> => this.get('/api/v1/audit', { limit });
}
