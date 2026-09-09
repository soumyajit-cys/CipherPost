/**
 * CipherPost Design Tokens — single source of truth for landing + dashboard.
 * Security-tool register: Wireshark technical credibility + Grafana density
 * + Linear motion polish + GitHub security severity semantics.
 * Dark-first, color reserved for severity.
 */

export const colors = {
  base: {
    950: '#0a0e14',
    900: '#0f141b',
    850: '#131a23',
    800: '#1a222d',
    750: '#1f2937',
    700: '#273442',
    600: '#334155',
    500: '#475569',
    400: '#64748b',
    300: '#94a3b8',
    200: '#cbd5e1',
    100: '#e2e8f0',
    50: '#f8fafc',
  },
  sev: {
    critical: '#f43f5e',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#8b9cb5',
  },
  positive: '#22c55e',
  accent: '#38bdf8',
  accentHover: '#0ea5e9',
} as const

export const severity = {
  critical: { label: 'Critical', color: colors.sev.critical, bg: 'bg-sev-critical', order: 5 },
  high: { label: 'High', color: colors.sev.high, bg: 'bg-sev-high', order: 4 },
  medium: { label: 'Medium', color: colors.sev.medium, bg: 'bg-sev-medium', order: 3 },
  low: { label: 'Low', color: colors.sev.low, bg: 'bg-sev-low', order: 2 },
  info: { label: 'Info', color: colors.sev.info, bg: 'bg-sev-info', order: 1 },
  none: { label: '—', color: colors.base[500], bg: 'bg-base-600', order: 0 },
} as const

export type SeverityKey = keyof typeof severity

export const typography = {
  sans: 'Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
  mono: '"JetBrains Mono", "SF Mono", "Fira Code", ui-monospace, monospace',
  scale: {
    xs: '11px',
    sm: '12px',
    base: '13px',
    lg: '15px',
    xl: '18px',
    '2xl': '24px',
    '3xl': '30px',
    '4xl': '36px',
    hero: 'clamp(32px, 5vw, 56px)',
  },
} as const

export const spacing = {
  xs: '4px',
  sm: '8px',
  md: '12px',
  lg: '16px',
  xl: '24px',
  '2xl': '32px',
  '3xl': '48px',
} as const

export const radius = {
  sm: '4px',
  md: '6px',
  lg: '8px',
  pill: '999px',
} as const

export const motion = {
  duration: { fast: '120ms', base: '180ms', slow: '260ms' },
  easing: { standard: 'cubic-bezier(0.2, 0, 0, 1)', entrance: 'cubic-bezier(0, 0, 0, 1)' },
} as const

// Tailwind class shortcuts for repeated patterns
export const cnSeverity = {
  critical: 'bg-sev-critical/15 text-sev-critical border-sev-critical/40',
  high: 'bg-sev-high/15 text-sev-high border-sev-high/40',
  medium: 'bg-sev-medium/15 text-sev-medium border-sev-medium/40',
  low: 'bg-sev-low/15 text-sev-low border-sev-low/40',
  info: 'bg-sev-info/15 text-sev-info border-sev-info/40',
  none: 'bg-transparent text-base-400 border-base-500/40',
} as const
