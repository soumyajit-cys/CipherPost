# Item 6 evidence: SSO against real Keycloak 26.8.0 (2026-10-05)

Result: **PASS** (live IdP exercised; nothing about other providers claimed).

## Lab setup (exact versions, local only)

- Keycloak **26.8.0** (released 2026-10-01 per GitHub; tarball
  `keycloak-26.8.0.tar.gz`, 165 MB, Apache-2.0 — run, not copied),
  on OpenJDK 21 (`java-21-openjdk-amd64`), `kc.sh start-dev --http-port=8888`
  (dev profile, H2 DB), bootstrap admin `admin`.
- Realm `cipherpost-test` (dev-only `sslRequired=NONE` for plain-HTTP lab),
  public client `cipherpost` (standard flow, PKCE S256, redirect
  `http://127.0.0.1:8899/*`), groups `mail-admins`/`mail-analysts`, users
  `alice` (admins) / `bob` (analysts), client `groups` membership mapper
  (ID+access tokens), accessTokenLifespan 120 s (30 s during expiry test,
  restored after).
- Our side: `CIPHERPOST_OIDC_ISSUER=http://127.0.0.1:8888/realms/cipherpost-test`,
  `CIPHERPOST_OIDC_CLIENT_ID=cipherpost`, claim rules mapping
  `*mail-admins*→admin`, `*mail-analysts*→analyst`.

## Verified end to end (our code, real IdP responses)

| Check | Result |
|---|---|
| Full code+PKCE login (alice, bob): authorize→form→required-action→code→exchange→verify | PASS (`test_keycloak_full_login_and_group_mapping`) |
| Group-to-role mapping from live `groups` claim | PASS (alice→admin, bob→analyst) |
| Key rotation: new RSA provider added (2 RS256 kids); fresh new-kid token accepted via unknown-kid single-refresh path | PASS (manual run 2026-10-05; kid `9H57…`) |
| Expiry: 30 s-lifetime token accepted fresh, rejected 45 s later ("Signature has expired") | PASS (manual + `test_keycloak_unknown_kid_refresh_and_expiry`) |
| Disabled user: Keycloak `user_disabled`, no code issued | PASS (`test_keycloak_disabled_user_rejected_and_restored`; bob re-enabled after) |
| State single-use + replay rejection | PASS |
| Realm state restored after tests (lifespan 120 s, bob enabled) | verified 2026-10-05 |

Automated: `backend/tests/test_phase6_keycloak.py` (4 tests, slow,
env-gated on `CIPHERPOST_TEST_KEYCLOAK_URL` +
`CIPHERPOST_TEST_KEYCLOAK_ADMIN_PASSWORD`; skips without them).
4 passed in ~41 s (expiry wait dominates) on 2026-10-05.

## Honest limits

- Lab harness quirks overcome (documented, not product issues): path-scoped
  auth cookies must be forwarded manually over plain HTTP; VERIFY_PROFILE
  first-login form needs exact profile fields (extra fields re-render).
- MFA in this task means our app-side TOTP (unchanged, fake-tested); no
  Keycloak-side MFA was configured or tested.
- Our `/auth/logout` and `revoke-all` session paths were not re-run live
  here (token-lifecycle primitives unchanged; fake-covered in Phase 3).
  Stating plainly so nobody over-reads this file.
- Keycloak left RUNNING on :8888 with the test realm for re-runs; creds are
  lab-only (`KeycloakLabAdmin123!`, `AliceLab123!`, `BobLab123!`).
