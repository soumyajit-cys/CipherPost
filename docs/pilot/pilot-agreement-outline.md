# Pilot agreement outline (NON-LEGAL — must be reviewed by counsel)

**This is a structured starting point, not an agreement and not legal
advice.** Nothing here is a legal conclusion. Before any pilot starts, a
lawyer for both parties must review, revise, and replace this outline with
a real agreement, and local law (data protection, monitoring/interception,
employment, sector rules) controls everywhere it differs.

## 1. Scope

- What CipherPost does in the pilot: passive analysis of SMTP/IMAP/POP3
  traffic metadata at the agreed capture point for the agreed duration.
- Environment: the pilot's own mail infrastructure only; no third-party
  systems contacted; no active probing except separately authorized.
- Explicitly out of scope: blocking, filtering, or modifying mail;
  automated enforcement; content inspection.

## 2. Data collected

- Exactly what is stored and what leaves the sensor: per the current
  `docs/pilot/data-handling-summary.md` (attached by reference, versioned
  by commit hash at signature).
- Pseudonymization mode selected by the pilot: full / truncated / hashed
  (default to be chosen by the pilot; recommend at least truncated).
- Raw-frame window (default 6 h) and that raw frames stay on the
  capture host.

## 3. Authorization confirmation

- The pilot confirms it has the authority to capture the traffic at the
  chosen point, including any internal consents required (employee
  monitoring notices under applicable law are the pilot's obligation —
  counsel to confirm wording and placement).
- Both parties confirm no third-party mail servers or external recipients
  will be probed or contacted by the tooling.

## 4. Retention

- Retention days per data type (defaults per `DEPLOYMENT.md`; pilot may
  shorten, never lengthen, without a documented reason).
- Legal hold: who may place one, on what ids, and the review date.
- End-of-pilot deletion: what is deleted, by whom, and the written
  confirmation (see data-handling summary "Delete everything").
- Backup handling: whether dumps may include pilot data and when backups
  are destroyed.

## 5. Support expectations (pre-1.0 honesty)

- Best-effort support, response targets from
  `docs/live-run/triage.md` (S1 same day, S2 24 h, S3 week) — stated as
  effort targets, **not an SLA or warranty**.
- Escalation contacts on both sides; issue reporting via the GitHub
  templates with redacted bundles.
- Known limitations acknowledged up front (synthetic + 28-capture lab
  precision only; TLS 1.3 certificate blindness; single-segment view —
  `docs/pilot-guide.md` and `docs/what-we-cannot-see.md`).

## 6. Feedback cadence

- Weekly check-in using `weekly-checkin-template.md`; labels recorded via
  the feedback flow; end-of-pilot survey.
- Feedback data ownership: labels and bundles remain usable by both
  parties for product improvement **only in aggregate** — no single
  pilot's data is exposed to others (see `pilot-metrics.md` aggregation
  rules); specifics to be settled by counsel.

## 7. Confidentiality

- Findings reference the pilot's infrastructure; both parties treat issue
  bundles, reports, and traffic statistics as confidential by default.
- Neither party publishes pilot-identifying metrics without written
  consent; aggregate, de-identified results may be published per counsel.

## 8. Warranty disclaimer

- The software is provided as-is, pre-1.0, with no warranty of accuracy,
  completeness, or fitness for any purpose, to the maximum extent
  permitted by law (counsel to draft the operative clause).
- CipherPost output is decision support for analysts, not a compliance
  certification.

## 9. Exit and deletion

- Either party may end the pilot with notice (duration to agree; e.g. 7
  days). On exit: data deletion per section 4, deletion confirmation in
  writing, and return/destruction of confidential materials.
- Survival: confidentiality and records of deletion survive exit.

---

*Sections a lawyer must at minimum review: 3 (authorization), 4
(retention/backup), 6 (feedback data ownership), 7 (confidentiality), 8
(warranty/limitation of liability). This outline intentionally contains no
choice of law, indemnity, or liability-cap language — that is counsel's
job, not this document's.*
