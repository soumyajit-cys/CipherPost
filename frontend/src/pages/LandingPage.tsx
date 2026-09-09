import { Link } from 'react-router-dom'
import { HeroMock } from '@/components/landing/HeroMock'

function MarketingHeader() {
  return (
    <header className="sticky top-0 z-30 border-b border-base-700/60 bg-base-950/80 backdrop-blur">
      <div className="mx-auto flex h-[52px] max-w-[1200px] items-center justify-between px-6">
        <Link to="/" className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded border border-accent/40 bg-accent/10">
            <span className="h-3.5 w-3.5 rounded-sm border-2 border-accent/70" />
          </span>
          <span className="text-[15px] font-bold tracking-tight text-base-50">
            Cipher<span className="text-accent">Post</span>
          </span>
          <span className="hidden rounded bg-base-800 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-base-400 sm:inline">
            NTRO PS 26159
          </span>
        </Link>
        <nav className="hidden items-center gap-6 text-[13px] font-medium text-base-300 md:flex">
          <a href="#how" className="hover:text-base-50 transition-colors">How it works</a>
          <a href="#capabilities" className="hover:text-base-50 transition-colors">Capabilities</a>
          <a href="#trust" className="hover:text-base-50 transition-colors">Trust</a>
          <a href="https://github.com/anomalyco/opencode" className="hover:text-base-50 transition-colors">Docs</a>
        </nav>
        <div className="flex items-center gap-2">
          <Link to="/app" className="hidden rounded border border-base-600 px-3 py-1.5 text-[13px] font-medium text-base-200 hover:bg-base-800 sm:inline-flex">
            Open dashboard
          </Link>
          <Link to="/app/live" className="rounded bg-accent px-3.5 py-1.5 text-[13px] font-semibold text-base-950 hover:bg-accent/90 transition-colors">
            See it live
          </Link>
        </div>
      </div>
    </header>
  )
}

function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="shrink-0 text-positive"><path d="M11.5 3.5L5.25 9.75 2.5 7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
  )
}

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-base-950 text-base-100 selection:bg-accent/30">
      <MarketingHeader />

      {/* HERO */}
      <section className="relative overflow-hidden border-b border-base-800">
        {/* subtle grid */}
        <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.04)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.04)_1px,transparent_1px)] bg-[size:32px_32px] [mask-image:radial-gradient(ellipse_at_center,black_60%,transparent_75%)]" />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-gradient-to-b from-accent/10 to-transparent" />
        <div className="relative mx-auto grid max-w-[1200px] gap-10 px-6 py-14 lg:grid-cols-[1.05fr_1.15fr] lg:py-20">
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-positive/30 bg-positive/10 px-2.5 py-1 text-[11px] font-medium tracking-wide text-positive">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-positive" /> Live — watches your wire, no uploads required
            </div>
            <h1 className="font-sans text-[clamp(32px,5vw,52px)] font-bold leading-[0.95] tracking-tight text-base-50">
              Email crypto
              <br />
              <span className="text-base-300">caught the instant</span>
              <br />
              it breaks.
            </h1>
            <p className="mt-4 max-w-[560px] text-[15px] leading-relaxed text-base-400">
              CipherPost is an always-on network forensic sensor for SMTP/IMAP/POP3. It reconstructs live sessions behind your SPAN/TAP, audits every TLS handshake and certificate chain, and alerts the moment a weak cipher, expired cert, or misconfiguration appears — with zero manual steps.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Link to="/app/live" className="inline-flex items-center gap-2 rounded bg-accent px-5 py-2.5 text-[14px] font-semibold text-base-950 hover:bg-accent/90 transition-colors">
                See it in action <span aria-hidden>→</span>
              </Link>
              <a href="https://github.com/anomalyco/opencode" className="inline-flex items-center rounded border border-base-600 bg-base-900 px-5 py-2.5 text-[14px] font-medium text-base-200 hover:bg-base-800 transition-colors">
                Read the docs
              </a>
            </div>
            <div className="mt-6 flex flex-wrap gap-4 text-[12px] text-base-500">
              <span className="inline-flex items-center gap-1.5"><CheckIcon /> Passive, no agents</span>
              <span className="inline-flex items-center gap-1.5"><CheckIcon /> Deterministic rules</span>
              <span className="inline-flex items-center gap-1.5"><CheckIcon /> Explainable AI</span>
            </div>
            <p className="mt-3 font-mono text-[11px] text-base-500">Deploys as a Docker service behind a SPAN port — CAP_NET_RAW only, no root required.</p>
          </div>

          <div className="relative">
            <HeroMock />
            <p className="mt-3 text-center font-mono text-[11px] text-base-500">Live mock — sessions animate in, critical finding pulses, timing is real.</p>
          </div>
        </div>
      </section>

      {/* PROBLEM */}
      <section className="mx-auto max-w-[1200px] px-6 py-14">
        <div className="grid gap-8 lg:grid-cols-[1.1fr_1.9fr]">
          <h2 className="text-[13px] font-semibold uppercase tracking-widest text-accent">The problem</h2>
          <div>
            <p className="text-[22px] font-semibold leading-tight tracking-tight text-base-50">
              TLS misconfigurations in email infrastructure are common — and invisible to standard monitoring.
            </p>
            <div className="mt-4 grid gap-4 text-[13px] leading-relaxed text-base-400 sm:grid-cols-3">
              <p>Mail gateways often negotiate legacy ciphers, short keys, or SHA-1 signatures that modern scanners never probe — because the vulnerability is in the negotiated session, not the open port.</p>
              <p>Standard NMS sees “port 25 open.” It misses RC4, 3DES, TLS 1.0, non-PFS, expired and self-signed certs, or a STARTTLS strip happening right now on the wire.</p>
              <p>Those gaps are directly exploitable: downgrade, MITM, and passive interception. CipherPost watches the actual byte stream and flags them the instant they occur.</p>
            </div>
          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section id="how" className="border-y border-base-800 bg-base-900">
        <div className="mx-auto max-w-[1200px] px-6 py-14">
          <h2 className="text-[13px] font-semibold uppercase tracking-widest text-accent">How it works</h2>
          <p className="mt-2 max-w-[560px] text-[13px] leading-relaxed text-base-400">A single streaming pipeline from packet to alert — same engine for live traffic and for archived PCAP replay.</p>

          <div className="mt-8 grid gap-3 md:grid-cols-5">
            {[
              { n: '01', t: 'Capture', d: 'Promiscuous sniff behind SPAN/TAP (eth0) with BPF on 25/587/465/110/995/143/993. Also accepts PCAP replay.', mono: 'AF_PACKET · scapy' },
              { n: '02', t: 'Reconstruct', d: 'TCP reassembly per 5-tuple, STARTTLS-aware, idle-timeout + memory-capped. Emits Session objects.', mono: '5-tuple · FIN/RST · 60s idle' },
              { n: '03', t: 'Forensics', d: 'TLS ClientHello/ServerHello, cipher suite, SNI, plus full X.509 chain validation against your trust store.', mono: 'cryptography · pyOpenSSL' },
              { n: '04', t: 'Score', d: '19 deterministic rules (NIST/OWASP) + GradientBoost risk score + IsolationForest anomaly, all SHAP-explained.', mono: '0–100 posture · SHAP' },
              { n: '05', t: 'Alert', d: 'Threshold + dedup + rate-limit, then webhook/Slack/SIEM. Findings persist to Postgres; raw frames roll off after hours.', mono: 'webhook · syslog CEF' },
            ].map((s) => (
              <div key={s.n} className="relative rounded-md border border-base-600/60 bg-base-850 p-4">
                <div className="font-mono text-[11px] tracking-wide text-accent">{s.n}</div>
                <div className="mt-1 text-[13px] font-semibold text-base-50">{s.t}</div>
                <p className="mt-1.5 text-[12px] leading-relaxed text-base-400">{s.d}</p>
                <div className="mt-3 font-mono text-[11px] text-base-500">{s.mono}</div>
                {s.n !== '05' && <span className="pointer-events-none absolute -right-[7px] top-1/2 hidden h-2 w-2 rotate-45 border-r border-t border-base-600 bg-base-850 md:block" />}
              </div>
            ))}
          </div>

          <div className="mt-6 overflow-x-auto rounded border border-base-700/60 bg-base-950 p-3 font-mono text-[11px] leading-relaxed text-base-400">
            <span className="text-base-500"># architecture — packet to dashboard</span>
            <div className="mt-1 whitespace-nowrap">
              live capture <span className="text-base-300">→</span> session reassembly <span className="text-base-300">→</span> TLS/cert forensics <span className="text-base-300">→</span> rules (primary) <span className="text-base-300">→</span> ML scoring + anomaly <span className="text-base-300">→</span> SHAP <span className="text-base-300">→</span> Postgres + SSE <span className="text-base-300">→</span> dashboard + alerts
            </div>
          </div>
        </div>
      </section>

      {/* CAPABILITIES */}
      <section id="capabilities" className="mx-auto max-w-[1200px] px-6 py-14">
        <h2 className="text-[13px] font-semibold uppercase tracking-widest text-accent">Capabilities</h2>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {[
            { title: 'Passive, zero-config live monitoring', desc: 'Deploys behind a mirror port. No agents on mail hosts, no config pushes. Watches the wire continuously with bounded memory — samples gracefully under load.', icon: '◉' },
            { title: 'Full TLS & X.509 forensics', desc: 'Parses ClientHello/ServerHello, cipher suite, SNI/ALPN, and the entire certificate chain — expiry, SAN, key length, signature, trust.', icon: '⬣' },
            { title: 'Deterministic, explainable rules', desc: '19 rules referencing NIST SP 800-52r2 & OWASP. Every finding cites the standard and the exact evidence — never a black box.', icon: '≡' },
            { title: 'AI risk + anomaly with SHAP', desc: 'GradientBoost posture score (0–100) plus IsolationForest over a rolling 7-day fleet baseline. Every score ships with SHAP contributions.', icon: '◈' },
            { title: 'Real-time alerting', desc: 'Webhook base with adapters for Slack and SIEM (syslog/CEF). Severity threshold, per-rule dedup, and rate-limiting prevent storms.', icon: '↗' },
            { title: 'Forensic reports', desc: 'Export JSON/HTML/PDF per session or per time window. Raw capture rolls off after hours; findings & metadata are retained indefinitely.', icon: '⎙' },
          ].map((c) => (
            <div key={c.title} className="rounded-md border border-base-600/60 bg-base-900 p-4">
              <div className="flex h-7 w-7 items-center justify-center rounded bg-base-800 font-mono text-[13px] text-base-300">{c.icon}</div>
              <div className="mt-3 text-[13px] font-semibold text-base-50">{c.title}</div>
              <p className="mt-1.5 text-[12px] leading-relaxed text-base-400">{c.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* LIVE PREVIEW */}
      <section className="border-y border-base-800 bg-base-900">
        <div className="mx-auto max-w-[1200px] px-6 py-14">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h2 className="text-[13px] font-semibold uppercase tracking-widest text-accent">Live dashboard preview</h2>
              <p className="mt-2 max-w-[560px] text-[13px] leading-relaxed text-base-400">What SOC sees: sessions appearing as they’re analyzed, findings ranked by severity, posture trending. This is the real dashboard — not a mock illustration.</p>
            </div>
            <Link to="/app" className="rounded bg-base-800 px-3 py-1.5 text-[13px] font-medium text-base-200 hover:bg-base-700">Open live dashboard →</Link>
          </div>

          <div className="mt-6 grid gap-4 lg:grid-cols-[1.4fr_0.9fr]">
            <div className="overflow-hidden rounded-lg border border-base-600/60 bg-base-950">
              <div className="flex items-center justify-between border-b border-base-700/60 bg-base-850 px-3 py-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-base-300">Live sessions</span>
                <span className="flex items-center gap-1.5 text-[11px] text-positive"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-positive" /> 3 events in last 5s</span>
              </div>
              <div className="divide-y divide-base-800">
                {[
                  { sev: 'critical', rule: 'RC4 cipher', tuple: '192.168.12.4:48210 → 10.0.1.5:25', score: '82' },
                  { sev: 'high', rule: 'TLS 1.0 deprecated', tuple: '10.0.1.22:39102 → 10.0.1.5:993', score: '64' },
                  { sev: 'high', rule: 'Self-signed chain', tuple: '192.168.12.9:50211 → 10.0.1.5:465', score: '71' },
                ].map((r, i) => (
                  <div key={i} className={`flex items-center gap-3 px-3 py-2.5 text-[12px] ${i === 0 ? 'animate-slide-in bg-sev-critical/10' : ''}`}>
                    <span className={`inline-flex rounded border px-1.5 py-px text-[11px] font-semibold uppercase tracking-wide ${r.sev === 'critical' ? 'border-sev-critical/40 bg-sev-critical/15 text-sev-critical' : 'border-sev-high/40 bg-sev-high/15 text-sev-high'}`}>{r.sev}</span>
                    <span className="font-mono text-base-200">{r.rule}</span>
                    <span className="ml-auto hidden font-mono text-base-400 sm:inline">{r.tuple}</span>
                    <span className="font-mono font-bold text-base-100">{r.score}</span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between bg-base-850 px-3 py-2 font-mono text-[11px] text-base-500">
                <span>Fleet posture · 7d trend</span>
                <span className="text-sev-medium">↗ +6.2 → 74/100</span>
              </div>
              {/* tiny sparkline */}
              <div className="h-10 w-full bg-base-950 px-2 pb-2">
                <svg viewBox="0 0 300 40" className="h-full w-full">
                  <polyline fill="none" stroke="#f97316" strokeWidth="1.8" points="0,28 30,26 60,30 90,22 120,18 150,20 180,14 210,16 240,10 270,12 300,8" />
                </svg>
              </div>
            </div>

            <div className="rounded-lg border border-base-600/60 bg-base-850 p-4">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-base-400">Why this fired</div>
              <p className="mt-2 font-mono text-[12px] leading-relaxed text-base-200">Cipher <span className="text-sev-critical font-semibold">TLS_RSA_WITH_RC4_128_SHA</span> negotiated. RC4 is prohibited by RFC 7465. <span className="text-base-400">Strong: ECDHE+AES-GCM or ChaCha20-Poly1305.</span></p>
              <div className="mt-3 rounded bg-base-900 p-2 font-mono text-[11px] text-base-400">SHAP: cipher_strength <span className="text-sev-high">+0.42</span> · tls_version <span className="text-sev-high">+0.18</span> · cert_key_len <span className="text-base-500">+0.01</span></div>
              <div className="mt-3 flex gap-2">
                <span className="rounded bg-base-800 px-2 py-1 font-mono text-[11px] text-base-300">NIST SP 800-52r2 §3.3.1</span>
                <span className="rounded bg-base-800 px-2 py-1 font-mono text-[11px] text-base-300">OWASP TLS Cheat Sheet</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* WHO IT'S FOR */}
      <section className="mx-auto max-w-[1200px] px-6 py-14">
        <h2 className="text-[13px] font-semibold uppercase tracking-widest text-accent">Who it’s for</h2>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {[
            { who: 'SOC teams', pain: 'You watch the SIEM all day, but email crypto posture is a blind spot. CipherPost turns that blind spot into a live feed with severity-ranked findings and SIEM-ready syslog CEF.' },
            { who: 'DFIR / Incident response', pain: 'When you need to know “what was negotiated when,” you need session-level forensics — handshake, cipher, cert chain, and SHAP-backed score — not just a port scan.' },
            { who: 'Enterprise & government mail admins', pain: 'Postfix/Exchange/Dovecot are hard to audit at scale. CipherPost verifies your fleet continuously and exports compliance reports per time window.' },
          ].map((p) => (
            <div key={p.who} className="rounded-md border border-base-600/60 bg-base-900 p-5">
              <div className="text-[13px] font-semibold text-base-50">{p.who}</div>
              <p className="mt-2 text-[12px] leading-relaxed text-base-400">{p.pain}</p>
            </div>
          ))}
        </div>
      </section>

      {/* TRUST */}
      <section id="trust" className="border-y border-base-800 bg-base-900">
        <div className="mx-auto max-w-[1200px] px-6 py-12">
          <h2 className="text-[13px] font-semibold uppercase tracking-widest text-accent">Trust & credibility</h2>
          <div className="mt-4 grid gap-6 md:grid-cols-[1.6fr_1fr]">
            <div className="space-y-3 text-[13px] leading-relaxed text-base-400">
              <p>Built against <span className="text-base-200">NIST SP 800-52r2</span> and the <span className="text-base-200">OWASP TLS Cheat Sheet</span>. Every finding cites the rule, the evidence (cipher ID, cert field, byte offset), and the standard — auditable by a third party without trusting the ML.</p>
              <p>ML is an augmentation, not a black box: risk score and anomaly flag are always paired with <span className="text-base-200">SHAP contributions</span> and a <span className="text-base-200">rule-vs-ML agreement</span> label, so operators can see why a score differs from the deterministic result.</p>
              <div className="flex flex-wrap gap-2 pt-2">
                <span className="rounded border border-base-600 px-2 py-1 font-mono text-[11px] text-base-300">NIST SP 800-52r2</span>
                <span className="rounded border border-base-600 px-2 py-1 font-mono text-[11px] text-base-300">OWASP TLS</span>
                <span className="rounded border border-base-600 px-2 py-1 font-mono text-[11px] text-base-300">SHAP explainable</span>
                <span className="rounded border border-base-600 px-2 py-1 font-mono text-[11px] text-base-300">Deterministic rules primary</span>
              </div>
            </div>
            <div className="rounded-md border border-base-600/60 bg-base-950 p-4 font-mono text-[11px] leading-relaxed text-base-400">
              <div className="text-base-300">Every score is backed by a visible reason.</div>
              <div className="mt-2 rounded bg-base-900 p-2">
                <div>finding: <span className="text-sev-high">TLS_RSA_WITH_RC4_128_SHA</span></div>
                <div>severity: <span className="text-sev-critical">critical</span> · rule: cipher-rc4</div>
                <div>evidence: <span className="text-base-200">cipher=0x0005 strength=0.12</span></div>
                <div>reference: <span className="text-accent">RFC 7465 §2</span></div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="mx-auto max-w-[1200px] px-6 py-14">
        <div className="rounded-lg border border-accent/20 bg-gradient-to-br from-accent/10 via-base-900 to-base-900 p-8 text-center">
          <h2 className="text-[24px] font-bold tracking-tight text-base-50">Put your email crypto on a live feed.</h2>
          <p className="mx-auto mt-2 max-w-[560px] text-[13px] leading-relaxed text-base-400">Deploy the sensor behind a SPAN port, or replay an archived PCAP — the same pipeline, same findings, same alerts. No manual uploads to triage.</p>
          <div className="mt-6 flex justify-center gap-3">
            <Link to="/app/live" className="rounded bg-accent px-5 py-2.5 text-[14px] font-semibold text-base-950 hover:bg-accent/90">See it live</Link>
            <a href="https://github.com/anomalyco/opencode" className="rounded border border-base-600 bg-base-850 px-5 py-2.5 text-[14px] font-medium text-base-200 hover:bg-base-800">View on GitHub</a>
          </div>
        </div>
      </section>

      <footer className="border-t border-base-800 bg-base-900">
        <div className="mx-auto flex max-w-[1200px] flex-col gap-6 px-6 py-8 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-2 text-[13px] font-semibold text-base-300">
            <span className="flex h-6 w-6 items-center justify-center rounded border border-accent/40 bg-accent/10">
              <span className="h-3 w-3 rounded-sm border-2 border-accent/70" />
            </span>
            CipherPost <span className="font-normal text-base-500">© {new Date().getFullYear()} · NTRO PS 26159</span>
          </div>
          <nav className="flex flex-wrap gap-4 text-[12px] text-base-500">
            <Link to="/app" className="hover:text-base-300">Dashboard</Link>
            <a href="https://github.com/anomalyco/opencode" className="hover:text-base-300">Docs</a>
            <a href="#trust" className="hover:text-base-300">Security</a>
            <span className="text-base-600">Dark-first · severity color only</span>
          </nav>
        </div>
      </footer>
    </div>
  )
}
