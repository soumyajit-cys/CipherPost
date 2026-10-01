# Licensing decision record — OWNER DECISION REQUIRED

No license has been chosen for CipherPost. Until one is, **all rights are
reserved by default** — do not assume you may reuse this code. The owner must
pick one of the paths below (or another) and record it here with date +
rationale.

## Option A: permissive (MIT / Apache-2.0)

- Anyone may use, modify, sell, and sublicense with minimal conditions
  (attribution; Apache-2.0 adds an explicit patent grant).
- Tradeoffs for this project: fastest enterprise adoption (legal teams already
  approve these); but competitors and MSSPs can sell CipherPost-based services
  without contributing back. Patent grant (Apache-2.0) is a plus for a
  security tool that may touch patented techniques.

## Option B: copyleft (AGPL-3.0)

- Anyone offering CipherPost as a network service must release their
  modifications — strong for a tool whose value is server-side analysis.
- Tradeoffs: many enterprises avoid AGPL code entirely (adoption friction for
  exactly the mail-admin audience Phase 3 targets); enforcement is hard for a
  small team; SaaS competitors just reimplement instead.

## Option C: open-core (permissive core + proprietary extras)

- Core detection engine under MIT/Apache-2.0; SSO/multi-org packs, advanced
  dashboards, or hosted offering commercial.
- Tradeoffs: keeps community + revenue path, but splits the codebase and
  complicates contributions (CLA needed); premature before any pilot revenue.

## Recommendation to the owner (not a decision)

Start Apache-2.0 if pilots are the priority (lowest friction, patent grant);
revisit open-core only with paying demand. Whatever is chosen: add the
`LICENSE` file, set `pyproject.toml` license field, and add REUSE-compliant
headers — none of that is done yet, deliberately.
