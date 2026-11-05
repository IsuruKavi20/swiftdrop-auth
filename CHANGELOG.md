# Changelog

All notable changes to the SwiftDrop Auth Service. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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

### Changed
- Integration guide: tokens now carry identity claims; `sub` stays the only user id (never link by email), and
  the claims are for display/prefill (up to 15 minutes old).
- **Breaking:** `POST /api/v1/auth/signup` now requires `name` (1–100 visible characters, every script; hidden,
  bidi and control characters rejected with `400 invalid-name`). Clients must send the "Full name" field.

### Security
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
