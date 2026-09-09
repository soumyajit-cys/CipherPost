/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"SF Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      colors: {
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
      },
      keyframes: {
        'slide-in': { '0%': { opacity: '0', transform: 'translateY(4px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        'pulse-sev': { '0%,100%': { boxShadow: '0 0 0 0 currentColor' }, '50%': { boxShadow: '0 0 0 4px transparent' } },
        'tick': { '0%': { transform: 'translateY(2px)', opacity: '0.6' }, '100%': { transform: 'translateY(0)', opacity: '1' } },
        'shimmer': { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
      },
      animation: {
        'slide-in': 'slide-in 180ms cubic-bezier(0.2,0,0,1)',
        'pulse-sev': 'pulse-sev 1.2s ease-out 1',
        'tick': 'tick 180ms ease-out',
      },
      boxShadow: {
        panel: '0 1px 2px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.04) inset',
      },
    },
  },
  plugins: [],
}