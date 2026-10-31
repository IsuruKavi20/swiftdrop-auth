# Changelog

All notable changes to the SwiftDrop Auth Service. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions: [Semantic Versioning](https://semver.org/).

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
