# Changelog

All notable changes to the SwiftDrop Auth Service. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Token introspection + revocation** (identity step 10, migration V24): `POST /oauth2/introspect` (RFC 7662;
  service clients with `token:introspect` only) reports a token inactive at once when it was revoked, the person is
  no longer ACTIVE, it was issued before their sessions last ended (`users.tokens_valid_after`), or its merchant
  client/service client is no longer valid; active answers carry the CURRENT roles. `POST /oauth2/revoke` (RFC
  7009) cancels refresh tokens (session ends) and access tokens (jti list, cleaned after expiry); always 200. Both
  in discovery. SwiftDrop guide: `docs/integration/introspection.md`.
- **Audit log core** (identity step 9a, migration V22): append-only `audit_log` (the app role cannot UPDATE/TRUNCATE,
  a trigger refuses changes for every role and removal of rows younger than a year), SHA-256 hash chain built in
  commit order under the shared write-order lock, chain verify, yearly retention with a checkpoint, and a nightly
  external anchor (`audit-anchor/` in the backup bucket). Details hold ids only (values with "@" are refused).
- **Audited actions** (step 9a): role grant/revoke, role applications withdrawn/decided, merchant decisions and
  status changes, account deleted, erasure confirmed/completed, email change requested/confirmed/undone, password
  changed, directory email reads, admin block/unblock/end sessions, audit exports; each in the action's transaction.
- **Admin API** (step 9b, migration V23 `user:manage-status`, `user:delete` for ADMIN): `GET /admin/users/{id}`,
  `POST /admin/users/{id}/block|unblock|sessions/end`, `DELETE /admin/users/{id}` (step 8 erasure), all with a
  required reason; never yourself, never the last active admin. `GET /admin/access-review`.
- **Audit API** (step 9c): `GET /admin/audit` (filters, newest first, `before` paging), `/admin/audit/export` (CSV,
  formula-safe, itself audited), `/admin/audit/verify`. Screen spec: `docs/integration/admin-frontend.md`.
- **Break-glass tool** (step 9e): `deploy/oke/break-glass.ps1` menu; each action runs the image once as a Job with the
  `break-glass` profile, same rules, audited as `BREAK_GLASS`. NetworkPolicy lets that Job reach Postgres/Redis.
- **Identity profile** (identity plan step 1): `name`, `given_name`, `family_name`, `picture_url`, `locale` on users
  (OpenID Connect claim names), with `profile_source` (USER/GOOGLE) and `profile_updated_at` (migration V11).
- Google login imports the profile from the signed ID token; a user-typed name is never overwritten, Google only
  fills empty fields; invalid claims are dropped without failing the login.
- **Identity claims in user access tokens** (identity plan step 2): `email`, `email_verified` and `name` (OpenID
  Connect names; `name` omitted when the account has none). Refreshed tokens carry the current values. Merchant
  (client-credentials) and dev test tokens carry none. Picture, phone and address are never put in a token.

- **My profile API** (identity step 3a): `GET /api/v1/me/profile` and `PATCH /api/v1/me/profile` (JSON Merge
  Patch; `If-Match` required: 428 without, 412 when stale). Profile photos only from trusted image hosts
  (`swiftdrop.profile.picture-hosts`, default `.googleusercontent.com`); Google photos from other hosts are dropped.

- **Email change request** (identity step 3b-1): `POST /api/v1/me/email-change` (current password required; 202
  always; confirmation link to the new address, notice to the old one; one open request per user; flood limits).
  New `account` module, migration V12, error codes `REAUTHENTICATION_FAILED`, `REAUTHENTICATION_REQUIRED`,
  `EMAIL_UNCHANGED`.

- **Email change confirmation** (identity step 3b-2): `POST /api/v1/auth/email-change/confirm {token}` (public,
  single use, 1 hour). The old address gets "email changed" with a 7-day undo link.

- **Email change undo** (identity step 3b-3): `POST /api/v1/auth/email-change/revert {token}` restores the old
  address (even after further changes), cancels open requests and ends all sessions (`EMAIL_CHANGE_UNDONE`, V13).

- **Password change** (identity step 3c): `POST /api/v1/me/password` (current password; sign-up rules; ends all
  sessions incl. this device's and returns fresh tokens; notice email; `PASSWORD_CHANGED`, V14).

- **Data export** (identity step 3d): `GET /api/v1/me/export` (JSON download; every module contributes its section
  through `PersonalDataExporter`; no secrets).

- **Account deletion** (identity step 3e): `DELETE /api/v1/me` (password; tombstone with status `DELETED`,
  real email removed, sessions ended, Google link removed via `AccountDeleted`; V15).

- **OpenID Connect** (identity step 4): discovery `/.well-known/openid-configuration`; `id_token` in login, refresh
  and Google responses (`typ JWT`, audience = frontend, never accepted as an access token); `GET/POST
  /oauth2/userinfo`. No authorization-code flow (not advertised).

- **Directory API** (identity step 5): service clients (`svc_…`, client credentials, secrets configured as SHA-256)
  with `directory:read` / `directory:read-email`; `GET /api/v1/directory/users/{id}`, `POST …/lookup` (≤100),
  `GET …/users` (role/status filters, SCIM paging ≤100, living accounts only). Email reads logged.

- **Identity events, part 1** (identity step 6a/6b): every change to a person is recorded in `identity_events` in
  the same transaction (per-person version, V17), and can be signed as a Security Event Token (RFC 8417,
  `typ secevent+jwt`), and pushed to configured receivers (6c, RFC 8935: `swiftdrop.events.receivers`, https only,
  retries with backoff, dead after 24 h, multi-pod safe with `SKIP LOCKED`, V18), and collectable by polling
  (6d, RFC 8936: `POST /api/v1/events/poll`, own receiver only, `events:read`; states DEAD vs REJECTED, V19).

- **Role applications, part 1** (identity step 7a): `POST/GET /api/v1/me/role-applications`, `DELETE …/{id}`
  (COURIER or DISPATCHER; one open per role; 7 days after a rejection; separation of duties: never COURIER and
  DISPATCHER together, also enforced by the admin grant endpoint). Permissions `role:approve-courier` (ADMIN,
  DISPATCHER) and `role:approve-dispatcher` (ADMIN). V20.
- **Role application decisions** (identity step 7b): `GET /api/v1/admin/role-applications` (only roles the caller may
  decide) and `POST …/{id}/decision` (APPROVE/REJECT with reason; no self-approval, enforced server-side; applicant
  re-checked at decision time; role + "roles changed" event in one transaction). The applicant is emailed the
  decision (with the reason) through the outbox (7c).
- **Role application hardening** (identity step 7d): decisions lock before reading (no lost concurrent decision),
  the approver is re-checked in the database, withdraw locks, queue `count` 1–100 (default 50), nobody grants a role
  to themselves (`CANNOT_GRANT_OWN_ROLE`), control characters removed from notes/reasons, queue rate limit 60/min.
- **Poll-only event receivers**: `push-url` is optional; a receiver without one is never pushed to and collects
  its events by polling (RFC 8936). Helm `eventReceivers`; Oracle: `swiftdrop-backend` poll-only, `events:read`.
- **Registered frontends**: `swiftdrop.frontends` (id, base-url, primary) replaces `swiftdrop.frontend.base-url` and
  `swiftdrop.cors.allowed-origins`. Google login accepts `?frontend=<id>`; email links follow the request's Origin
  (exact match); unknown → primary; CORS = the same list. Helm `frontends` replaces `frontendBaseUrl` and
  `corsAllowedOrigins` (**breaking config change**).
- **Nightly encrypted backups** (Helm `backup`, off by default): CronJob `pg_dump` → `age` → S3-compatible storage
  (Oracle Object Storage), read-only role `backup_reader`, write-only storage key, own NetworkPolicy; backup image
  `deploy/backup` built, scanned and published (x86 + ARM) by CI; `deploy/backup/test-backup.sh` (end-to-end restore
  test) and `deploy/oke/restore-test.ps1` (production restore check).
- **Erasure everywhere** (identity step 8, V21): `POST /api/v1/directory/erasure/{userId}/confirm` (service client of
  the receiver, permission `erasure:confirm`); nightly hard delete of tombstones once every receiver confirmed or after
  30 days (multi-pod safe), `erasure_log` (ids + dates, 60 days); the backup job also stores the encrypted list of
  deleted ids; `deploy/oke/reapply-erasures.ps1` erases them again after a restore.

### Changed
- Test JVM bounded (failsafe `-Xmx1g`, max 6 cached Spring test contexts) after an out-of-memory crash.
- Integration guide: tokens now carry identity claims; `sub` stays the only user id (never link by email), and
  the claims are for display/prefill (up to 15 minutes old).
- **Breaking:** `POST /api/v1/auth/signup` now requires `name` (1–100 visible characters, every script; hidden,
  bidi and control characters rejected with `400 invalid-name`). Clients must send the "Full name" field.

### Security
- Step 6 review fixes: identity events commit in sequence order (no event can be skipped by the delivery
  bookmark), deleting an account wipes the personal data of its earlier events, events older than 30 days are
  deleted, sends are leased in small batches (no double send), a broken event can't block delivery, only real changes
  are recorded, malformed poll ids answer 400.
- Step 3 review fixes: every "my account" action requires an active account (a deleted/disabled account's
  still-valid token gets 401); deletion erases the email-change history; wrong passwords on sensitive actions use
  their own counter (V16) instead of the login lockout; undo links last 72 hours; deletion is idempotent and drops
  roles.
- Fixed a lost update: an email-change job could re-open a request cancelled meanwhile (now row-locked).
- Reclaiming a pre-hijacked account through Google also removes the profile the attacker typed.
- Session start re-checks the account on the locked, fresh row: an account disabled between the password check and
  token issuing gets no tokens (race found in review).
- Name validation blocks bidi overrides, zero-width and blank-looking characters, and line separators; photo URLs
  must be exactly `https://` with a real host and no credentials (also enforced by a database CHECK).

## [1.0.0] - 2026-10-31

First release: Module 1 (Identity, Access & Auth) of SwiftDrop as a separate, deployable service.

### Added
- **Signup** with email verification: always `202` (no account enumeration), NIST SP 800-63B password rules,
  breached-password check via Have I Been Pwned (k-anonymity), Argon2id hashing.
- **Email verification**: one-time links (only SHA-256 stored), reliable sending through an outbox, resend with cooldown.
- **Login**: one answer for every failure, constant timing (dummy hash), RS256 access tokens (`typ: at+jwt`, 15 min,
  roles + entitlements, no personal data).
- **Token verification for other services**: JWKS endpoint (`/.well-known/jwks.json`), key rotation with previous keys,
  integration guide (`docs/integration/verifying-swiftdrop-tokens.md`).
- **Sessions**: rotating refresh tokens with reuse detection (RFC 9700), 1 day idle / 7 days absolute, logout.
- **Google login**: OpenID Connect authorization code flow with PKCE, account linking by Google `sub`,
  pre-hijacking and login-CSRF defences, one-time hand-off code to the frontend.
- **Roles and permissions**: CUSTOMER, MERCHANT, COURIER, DISPATCHER, ADMIN with permissions in tokens; ownership
  checks (a courier cannot read another courier's deliveries); admin role API; first admin from configuration.
- **Merchants**: application, admin approval / rejection / suspension, OAuth 2.0 client credentials for merchant
  software (`/oauth2/token`).
- **Abuse protection**: per-IP rate limits (token buckets) on all public endpoints, progressive temporary lockout,
  request size limit, bulkhead for password hashing, strict JSON.
- **Operations**: RFC 9457 Problem Details errors with request ids, CORS allow-list, health endpoint, production
  profile that refuses to start with missing or unsafe settings, Docker image.

### Known limitations
- Rate-limit buckets are in memory: correct for one instance; several instances need a shared store (Redis).
- No audit log, no MFA, no "forgot password" yet (planned).
- The Google client must be switched from Testing to In production before real users can sign in with Google.
