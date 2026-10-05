# SSO (OIDC) and MFA setup

CipherPost supports OIDC authorization-code + PKCE login alongside local
accounts, plus TOTP MFA for local accounts. Everything defaults to off/deny.

## OIDC configuration

```bash
CIPHERPOST_OIDC_ISSUER=https://idp.example.com/realms/cipherpost
CIPHERPOST_OIDC_CLIENT_ID=cipherpost
CIPHERPOST_OIDC_CLIENT_SECRET=...        # never commit
CIPHERPOST_OIDC_SCOPES="openid email profile"
CIPHERPOST_OIDC_JWKS_CACHE_SECONDS=600
```

Validation is fail-closed: RS256 pinned (unsigned and symmetric tokens
rejected before any claim is read), issuer/audience/expiry/nonce required,
unknown `kid` triggers one JWKS refresh then rejection. Tested against a
local fake OIDC provider in `backend/tests/test_phase3_sso_mfa.py` AND
against real Keycloak 26.8.0 in `backend/tests/test_phase6_keycloak.py`
(slow, env-gated): full code+PKCE login, group-to-role mapping, key-rotation
acceptance, short-lifetime expiry rejection, disabled-user rejection. See
`docs/evidence/sso-keycloak.md`. No Okta/Azure/Google compatibility is
claimed — nothing about other providers. To verify yours, point a staging
deploy at it and watch `auth.sso.failed` in the audit log.

## Claim mapping and provisioning

```bash
CIPHERPOST_OIDC_CLAIM_RULES='[{"claim":"groups","match":"*@mail-admins","role":"admin","org":"default"}]'
CIPHERPOST_OIDC_DEFAULT_ROLE=auditor   # least privilege when nothing matches
CIPHERPOST_OIDC_DEFAULT_ORG=default
CIPHERPOST_OIDC_JIT_PROVISIONING=true  # set false to require pre-created users
```

First matching rule wins; unknown roles are ignored. JIT creates users with a
random unusable password (local login impossible) and binds `oidc_sub`; an
email whose `oidc_sub` differs is rejected as an account conflict.

## Disabling password login + break-glass

```bash
CIPHERPOST_DISABLE_PASSWORD_LOGIN=true
CIPHERPOST_BREAK_GLASS_EMAIL=ops-admin@example.com     # empty = disabled
CIPHERPOST_BREAK_GLASS_PASSWORD=...                    # empty = disabled
```

The break-glass account must be an existing, active **platform admin** user;
every attempt is audited (`auth.login.break_glass[.failed]`). Keep it disabled
until SSO is verified end to end.

## TOTP MFA for local accounts

1. `POST /api/v1/auth/mfa/enroll` → scan `otpauth_uri`, store the 10 recovery
   codes (shown once, stored hashed).
2. `POST /api/v1/auth/mfa/confirm` with a code from the app.
3. Logins then return `{mfa_required, mfa_ticket}`; exchange via
   `POST /api/v1/auth/mfa/verify` with a code or a (single-use) recovery code.

Secrets are AES-GCM encrypted with a JWT-secret-derived key (rotation
invalidates them — re-enroll). The MFA step locks after 5 failures / 5 min.
`CIPHERPOST_MFA_REQUIRED_ORGS="acme,globex"` mandates MFA per org.
Admins can reset MFA via `POST /api/v1/auth/mfa/disable` (audited).

## Sessions

- `POST /api/v1/auth/logout` revokes the presenting token (deny-listed to expiry).
- `POST /api/v1/auth/revoke-all` bumps the user's session version, killing all
  sessions (use after role changes or suspected compromise).
- Default session lifetime: `CIPHERPOST_JWT_EXPIRY_SECONDS` (24 h).
