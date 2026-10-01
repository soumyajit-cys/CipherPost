# API versioning and deprecation policy

Base path `/api/v1` is stable. The machine-readable contract is
`docs/openapi.json`, regenerated from the app; CI (`scripts/check_openapi_break.py`)
fails on unintended breaking changes.

## What is stable

- Path + method + required query/body fields of every route in `docs/openapi.json`.
- Success response shapes (new optional fields may be added at any time).
- Error shape `{detail: string}` with the documented status codes.
- Pagination: `limit` (default 50, max 200) + `offset`; `page` (1-based) and
  `per_page` are accepted as aliases everywhere paginated.
- Rate limiting is signaled with `Retry-After` (seconds) on 429/locked 401s.

## Deprecations

1. Announced in CHANGELOG.md with the replacement route/field.
2. Minimum notice: **one minor release or 90 days**, whichever is longer.
3. During notice the old route keeps working; sunset version is announced up front.
4. Removal bumps the minor version and is a headline CHANGELOG entry.

## Major versions

- A `/api/v2` (or 1.0→2.0) is only introduced for unavoidable breaking change;
  v1 is then maintained for the notice period above.
- Local-user password login and agent-token ingest are long-term stable
  interfaces; SSO/OIDC claim rules are configuration, not API, and may extend
  additively.
