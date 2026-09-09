# CipherPost Design System — Shared tokens for Landing + Dashboard

**Register:** Wireshark technical credibility + Grafana density + Linear/Vercel typographic polish + GitHub security severity semantics.  
**Principle:** Dark-first, neutral grayscale base; color is reserved for severity/status only.

## Tokens

**Colors — `frontend/src/design/tokens.ts` / `tailwind.config.js`**
- Base: 950 `#0a0e14` → 50 `#f8fafc` (950 is canvas, 850 is panel, 700/600 borders, 400 muted text, 100/50 light)
- Severity: critical `#f43f5e`, high `#f97316`, medium `#eab308`, low `#3b82f6`, info `#8b9cb5`
- Semantic: positive `#22c55e`, accent `#38bdf8` (interactive only)
- Rule: severity colors appear ONLY on badges, table cells, chart series, status dots. Never for decoration.

**Typography**
- Sans: Inter (UI text, headings, body) — weights 400/500/600/700
- Mono: JetBrains Mono (cipher names, fingerprints, hex, 5-tuples, offsets) — 400/500
- Scale: xs 11px (labels), sm 12px, base 13px (body), xl 18px, 2xl 24px, 4xl 36px, hero clamp(32–56px)

**Spacing & Radius**
- Spacing: xs 4, sm 8, md 12, lg 16, xl 24, 2xl 32, 3xl 48
- Radius: sm 4, md 6, lg 8, pill 999
- Panel: `rounded-md border border-base-600/60 bg-base-850 shadow-panel`

**Motion**
- Duration: fast 120ms, base 180ms, slow 260ms
- Easing: standard `cubic-bezier(0.2,0,0,1)`
- Allowed: slide-in for new rows, tick for numbers, pulse-sev for critical findings, shimmer for skeletons. No gratuitous animation.

## Component Patterns

**SeverityBadge** — `sev-*/15` bg + `sev-*` text + border `/40`, uppercase 11px tracking-wide. Pulse on critical (`animate-pulse-sev` once).

**DataTable** — sticky header (`position: sticky top-0 bg-base-850`), 12px dense rows, tabular-nums, severity cells carry left-border accent (2px). Sort affordance: `↑↓` only on sortable columns.

**ScoreGauge** — ring + inset shadow using severity-derived hex at 13% opacity. Animates via `transition-colors` + `tick`.

**CertChainViewer** — vertical spine (`border-l`), nodes with status dot (ok → positive, untrusted → high, expired → critical). Indent per level.

**SHAP ExplanationPanel** — horizontal bars, width = |impact| normalized, color by sign (positive=high, negative=low). Mono feature names.

**LiveIndicator** — persistent dot in header: `connected` → `bg-positive animate-pulse` + "Streaming" label; `disconnected` → `bg-sev-critical` + reconnecting text. Always visible on live routes.

**Empty/Loading/Error** — empty: centered icon + title + hint + primary action; loading: thin shimmer bar + skeleton rows; error: inline `sev-critical/10` banner with retry. Same panel chrome as populated states.

## Landing ↔ Dashboard Coherence

Both surfaces import `design/tokens.ts` and `tailwind.config.js`. Landing hero mock reuses actual dashboard `DataTable`/`SeverityBadge`/`ScoreGauge` components with animated mock data, so screenshot is not abstract. Typography pairing (Inter + JetBrains Mono) and severity-only color rule are enforced in both.
