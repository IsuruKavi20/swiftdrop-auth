# Module 1: Identity, Access & Auth Service — Full Build Plan
**Owner:** Pair 1 · **Built custom (Option B)** · Standalone service, personally reusable later
**Tags used below:** 🔵 = required by the brief · 🟢 = enterprise-level addition (not required, but what makes this production-grade)

---

## 1. Scope boundary (what this module is NOT)

To avoid overlap with other modules:
- **Webhooks** (merchant notifications on status change) are **Module 4's** job, not this module's. This service never sends a webhook.
- **Notifications** (email/SMS) are **Module 5's** job.
- This service's only output to the rest of the system is: a validated identity (JWT), a role, and a public key others use to check tokens themselves.

---

## 2. What the brief actually requires vs. what we're adding

| Brief requirement (🔵) | Exact wording |
|---|---|
| Customer signup/login + Google login | "Secure signup and login, including 'Login with Google' (OAuth 2.0)" |
| Merchant registration + admin approval | "Merchant registration with an admin approval step" |
| Merchant API auth | "...secured API using API keys **or** OAuth 2.0 client credentials" (brief allows either, not both) |
| Courier login | "Login and authentication" |
| RBAC | "Role-based access control for Customer, Merchant, Courier, and Dispatcher/Admin" |
| JWT + OAuth | "JWT-based authentication for the application, plus OAuth 2.0 for social login or merchant API access" |
| OAuth sequence diagram | Required in design docs |
| Courier isolation test | "a courier cannot access another courier's deliveries" — explicitly named test |
| Demo | Google login must be shown live |

| Our additions (🟢) | Why |
|---|---|
| Argon2id password hashing with tuned parameters | Brief just says "secure"; this is the current standard, not bcrypt/MD5 |
| Refresh token rotation + reuse detection | Prevents a stolen refresh token from being reused silently |
| JWKS key publishing + rotation with overlap window | Lets other services verify tokens without calling us, and without breaking on key rotation |
| Rate limiting / lockout on login | Brute-force protection, not mentioned in the brief but expected of "enterprise" |
| Audit log of auth events | The "Accounting" part of AAA; not in the brief but strengthens the admin story |
| Shared verification library for teammates | Makes this a real reusable asset + keeps other pairs from writing their own auth code |
| Standalone deployable, own schema | Supports your personal reuse goal; also satisfies "modular monolith with a BFF" per the brief's own example |

---

## 3. Technology stack (researched, with reasons)

| Concern | Choice | Why |
|---|---|---|
| Language/runtime | Java 25 (LTS) | Matches team's Spring Boot 4.1 baseline |
| Framework | Spring Boot 4.1 + Spring Security 7 | Current supported line |
| JWT library | **Nimbus JOSE+JWT** | What Spring Security's own OAuth2 support uses internally; has built-in JWKS caching — don't use a lighter library like `jjwt` here |
| Password hashing | **Argon2id** (via Spring Security Crypto's `Argon2PasswordEncoder`) | Current best-practice winner of the Password Hashing Competition, stronger than bcrypt against GPU cracking |
| Google login | `spring-boot-starter-oauth2-client` | Handles Authorization Code + PKCE automatically for browser logins — don't hand-roll PKCE |
| Database | PostgreSQL 17 + Flyway, **own schema** (`identity`) | Keeps this module's migrations independent of the rest of the team |
| Rate limiting | **Bucket4j** (in-memory for Week 1–3; Redis-backed `ProxyManager` once there's more than one instance) | Standard Spring Boot rate-limiting library; key by **username**, not just IP, so shared networks don't get wrongly blocked |
| Internal auth-check cache | Caffeine (in-process cache for JWKS fetched by other services — their side, but document it) | Avoids a network call on every request |
| Testing | JUnit 5, Testcontainers (real Postgres), Spring Security Test | No mocks for the database in integration tests |
| Containerization | Docker (own Dockerfile), added to the team's shared `docker-compose.yml` by Pair 4 | This service is one more container, not special |

---

## 4. Database schema (`identity` schema — yours alone)

| Table | Purpose |
|---|---|
| `users` | id, email, password_hash (nullable if Google-only), status (ACTIVE/LOCKED/DISABLED), created_at |
| `oauth_accounts` | user_id, provider ("google"), provider_user_id — links a Google login to a `users` row by email |
| `roles` | id, name (CUSTOMER / MERCHANT / COURIER / DISPATCHER / ADMIN) |
| `permissions` | id, name (e.g. `parcel:assign`, `merchant:approve`) 🟢 |
| `role_permissions` | role_id, permission_id — many-to-many 🟢 |
| `user_roles` | user_id, role_id |
| `merchants` | user_id, business_name, status (PENDING/APPROVED/REJECTED), approved_by, approved_at |
| `merchant_api_credentials` | merchant_id, client_id, client_secret_hash OR api_key_hash, created_at, revoked_at |
| `refresh_tokens` | token_hash, family_id, user_id, issued_at, consumed_at (null = still valid), replaced_by 🟢 |
| `login_attempts` (or Bucket4j/Redis, not DB) | optional persistence of lockout state if not using Redis |
| `auth_audit_log` | event_type (LOGIN_SUCCESS/LOGIN_FAILED/ROLE_CHANGED/MERCHANT_APPROVED/TOKEN_REUSE_DETECTED), user_id, ip, timestamp, detail 🟢 |

---

## 5. API surface

### Public (used by the frontend / merchants)
| Endpoint | Purpose | Brief/Extra |
|---|---|---|
| `POST /auth/signup` | Email/password signup | 🔵 |
| `POST /auth/login` | Email/password login → access + refresh token | 🔵 |
| `GET /auth/google/login` → redirect, `GET /login/oauth2/code/google` callback | Google OAuth flow | 🔵 |
| `POST /auth/refresh` | Exchange refresh token for a new access token (rotates it) | 🟢 (rotation logic) |
| `POST /auth/logout` | Revoke the current refresh token family | 🟢 |
| `POST /merchant/register` | Merchant signs up → `PENDING` | 🔵 |
| `POST /merchant/{id}/api-credentials` | Issue API key / client-credentials **after** approval | 🔵 |

### Admin
| Endpoint | Purpose |
|---|---|
| `GET /admin/merchants?status=PENDING` | Approval queue |
| `POST /admin/merchants/{id}/approve` \| `/reject` | Approve/reject + auto-provision credentials on approve |
| `GET /admin/users`, `PATCH /admin/users/{id}/disable` | User management |
| `GET /admin/audit-log` | 🟢 Accounting |

### Internal (used by other modules, not the public internet)
| Endpoint | Purpose |
|---|---|
| `GET /.well-known/jwks.json` | Publishes your public signing key(s) for other services to verify tokens offline |
| `POST /internal/token/introspect` (optional fallback) | Only needed if a service can't do local JWT verification |

---

## 6. Shared middleware / library (what you hand your teammates)

A small published library (`swiftdrop-auth-client`, versioned e.g. `1.0.0`) containing:
1. A **servlet filter** that reads the `Authorization: Bearer <token>` header, verifies the signature using the cached JWKS, and populates `SecurityContext` with the user's ID + role + permissions.
2. A `@RequireRole("DISPATCHER")` / `@RequirePermission("parcel:assign")` annotation + AOP check, so other pairs write one line instead of auth logic.
3. A `JwksCache` component — fetches your public key once, caches it 10–60 min, refetches only on an unknown `kid`.
4. A **test-token helper** for their unit tests (`TestTokens.forRole(COURIER)`), so they never need your service running to write tests.

**What you document for them (the actual deliverable, not just code):**
- Required header format
- Exact role name strings
- Error responses (401 missing/invalid token, 403 wrong role) and their shape
- How to get a working test token locally before your service is finished (ship this in Week 1)

---

## 7. Security controls checklist (build these in, don't bolt on later)

| Control | Detail |
|---|---|
| Password hashing | Argon2id, tuned to ~250ms per hash on your dev machine (start: time cost 2, memory 65536 KB, parallelism 2 — adjust after measuring) |
| JWT signing | RS256 only — **pin the algorithm allow-list**, never trust the token's own `alg` or `jku` header |
| Access token lifetime | 10–15 minutes |
| Refresh token | One-time use; store only its **hash**; tied to a "family" (= one session) |
| Reuse detection | If a refresh token is presented twice, **revoke the whole family** and force re-login; log it as `TOKEN_REUSE_DETECTED` |
| Key rotation | When you rotate your signing key, publish old + new in JWKS together for ~24h so in-flight tokens don't break |
| Rate limiting | Bucket4j, keyed by username (not just IP); lock the account after N failed attempts within a window |
| Google OAuth | Authorization Code + PKCE (Spring handles this); map Google email → existing user or create one; **role is never taken from Google**, always from your own DB |
| Transport | Tokens never touch `localStorage`; delivered via the BFF/gateway pattern as an HttpOnly cookie to browsers (gateway holds the real token) |
| CORS | Locked to your own frontend origin(s) only |
| PII | Never log raw passwords, tokens, or full phone numbers/addresses; mask in logs (`077****123`) |
| Secrets | Signing key + Google client secret from environment variables, never committed |

---

## 8. Build order (fits inside the team's Week 1–5 timeline)

| Week | What you build | Unblocks |
|---|---|---|
| **1** | Users/roles/permissions schema + Flyway migrations; signup/login with Argon2id; JWT issuing (access+refresh, unrotated first draft); **test-token endpoint + JWKS endpoint published** | Every other pair can start building against roles immediately |
| **2** | Google OAuth login + account linking by email; merchant registration → `PENDING`; admin approve/reject + auto-issue API credentials | Module 4 (merchant API) can start integration |
| **3** | Refresh token rotation + reuse detection + family revocation; rate limiting/lockout with Bucket4j; shared verification library v1.0.0 published to the team | Everyone switches from test tokens to the real thing |
| **4** | Admin user management UI + merchant approval UI + reports dashboard (your frontend scope); audit log + admin audit viewer | — |
| **5** | Security hardening pass: algorithm allow-list check, JWKS rotation drill, ZAP scan on your own endpoints, full role×endpoint test matrix, courier-isolation test (coordinate with Module 3) | Coverage gate, demo readiness |

---

## 9. Testing plan

| Type | What to test |
|---|---|
| Unit | Argon2id hash/verify round-trip; JWT issue/verify; token expiry; permission-check logic |
| Integration (Testcontainers Postgres) | Signup→login→refresh flow; merchant approve→credentials issued; reuse detection triggers family revocation |
| Security | Role × endpoint matrix (every role against every protected endpoint) 🔵 required; **courier cannot access another courier's data** 🔵 required (shared test with Module 3's data, but the rule is yours); lockout after N failed logins; rejected `alg:none` token; expired token rejected |
| Contract | Shared library's filter correctly rejects a tampered token, an expired token, and a token signed with the wrong key |

**Coverage target:** ≥ 75% backend, consistent with the team-wide gate.

---

## 10. Diagrams required for the design doc

1. **OAuth 2.0 / Google login sequence** 🔵 (explicitly required)
2. **Admin/auth use case diagram**
3. 🟢 Refresh token rotation + reuse-detection state diagram (strong addition, shows depth)
4. Your section of the ER diagram (the `identity` schema tables)

---

## 11. Deployment notes

- Own Dockerfile, non-root user, healthcheck on `/actuator/health`.
- Added as one more service in Pair 4's shared `docker-compose.yml` — you provide the Dockerfile + env var list, Pair 4 wires it into compose.
- Env vars: `DB_URL`, `DB_USER`, `DB_PASSWORD`, `JWT_SIGNING_KEY` (or keystore path), `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`.
- Other services only need `AUTH_SERVICE_JWKS_URL` as config — never a shared secret.

---

## 12. Risks specific to this module

| Risk | Mitigation |
|---|---|
| Building custom auth takes longer than Keycloak would | Time-box: Week 1 must ship *something* teammates can get test tokens from, even before rotation/Google are done |
| A real vulnerability slips in (this is the highest-stakes module to get wrong) | Follow section 7's checklist literally; get a teammate or TA to review the token-verification code specifically |
| Shared library breaks other pairs' builds on an update | Semantic version it; announce breaking changes; keep old version available for a few days |
| Bucket4j in-memory limiter doesn't survive multiple instances | Fine for the demo (likely one instance); document Redis upgrade path, don't build it unless the team actually scales out |

---

## 13. Password policy — NIST SP 800-63B (current standard, 2026)

This is the actual current guidance, and it corrects a very common student-project mistake: **more rules ≠ more secure.**

| Rule | What NIST actually says |
|---|---|
| Minimum length | **8 characters minimum**, but *encourage* 15+; your system must **accept at least 64 characters** so people can use passphrases |
| Complexity (uppercase/number/symbol requirements) | **Do not mandate this.** Forcing "1 uppercase, 1 number, 1 symbol" is outdated advice — it pushes people toward predictable patterns like `Password1!` |
| Forced periodic rotation ("change your password every 90 days") | **Do not require this.** Only prompt a password change when there's actual evidence of compromise |
| Character set | Accept printable ASCII, Unicode, and spaces — don't block emoji or non-English characters |
| **Breach-list check** 🟢 | **Required by current guidance**, not just a nice-to-have: check new/changed passwords against a list of known-breached passwords (e.g. via the HaveIBeenPwned k-anonymity API, which lets you check without sending the real password over the network), plus block the app/company name and the username itself as a password |

**What to actually build:** a simple length check (8–64), a breach-list check against HIBP's API (or a bundled common-password list if you want to avoid the external call), and nothing else. This is *less* code than a complexity-rule validator, and it's the version that's actually correct in 2026 — a good thing to state explicitly in your design doc, since many reviewers still expect the old complexity-rule approach.

---

## 14. Account lockout — exponential backoff, not permanent lockout

Permanent lockout after N failed attempts is itself a vulnerability: an attacker can lock a real customer out of their own account just by typing wrong passwords on purpose (this is called a **denial-of-service via lockout**). The current best practice is **exponential backoff** instead:

- Allow a handful of failures silently (just count them).
- After that, each further failure increases the lockout *delay*, doubling each time (e.g. 2s → 4s → 8s... capped around 15 minutes) — rather than locking forever.
- A genuine typo costs the real user a couple of seconds; a scripted attacker's guessing becomes too slow to be worth it.

**Avoid leaking whether an account exists** (this is its own OWASP risk — "account enumeration"):
- Return the **exact same error message and HTTP status** whether the email doesn't exist, the password is wrong, or the account is locked. Never return a distinct "this account is locked" message.
- Keep **response timing the same** in all three cases — e.g. still run a dummy Argon2id check even for an email that doesn't exist, so a timing difference doesn't give it away.
- Don't persist failed-login records for emails that don't exist in your system at all — only log them as noise, not as an auditable security event — otherwise an attacker can flood your `login_attempts` table with junk.

---

## 15. Forgot-password flow 🟢 (not explicitly in the brief, but expected of a real auth system)

Based on the OWASP Forgot Password Cheat Sheet:

1. User submits their email. **Always respond with the same message** ("if that email exists, we've sent a reset link") regardless of whether the account actually exists — this is the same anti-enumeration rule as login.
2. Generate the reset token with a **cryptographically secure random generator** (not `Math.random()` — use `SecureRandom` or Nimbus's built-in generator), long enough to resist brute-forcing, and store only its **hash** in the DB (same pattern as refresh tokens).
3. Token is **single-use and time-limited** (commonly 15–60 minutes) — invalidate it the moment it's used, and expire it automatically after that window.
4. **Rate-limit** reset requests per account/email, so an attacker can't flood someone's inbox.
5. Build the reset link from a **hardcoded domain**, never from the request's `Host` header (a classic "host header injection" trick to redirect reset links to an attacker's site).
6. After a successful reset: email a confirmation (never the new password itself), and **revoke all existing refresh token families** for that user, forcing every other logged-in session to log in again.
7. Don't auto-login the user after reset — send them to the normal login screen.

---

## 16. CSRF and cookies — the BFF-specific detail

Spring Security enables CSRF protection by default, and there's one detail that matters a lot for your architecture specifically: the **default CSRF token storage is the HTTP session**, which doesn't exist in a stateless JWT-style API. Since you're using the BFF/gateway pattern (session cookie at the gateway, not raw tokens in the browser), here's the correct split:

- **At the gateway/BFF (browser-facing):** keep CSRF protection **on**. Use `CookieCsrfTokenRepository` so the frontend JavaScript can read the token and send it back in a header — Spring has a ready-made `.csrf(csrf -> csrf.spa())` configuration specifically for this single-page-app case, including protection against the BREACH attack (which could otherwise guess the token by observing response compression).
- **At your internal auth service and other backend services (not directly browser-facing, authenticated by bearer token in the `Authorization` header):** CSRF protection can be **disabled**, because CSRF is specifically an attack against cookie-based browser sessions — a bearer token in a header isn't automatically attached by the browser the way a cookie is, so there's nothing for CSRF to exploit there.
- **Cookie attributes**, regardless: `HttpOnly` (JavaScript can't read it), `Secure` (HTTPS only), `SameSite=Lax` or `Strict` on the session cookie itself.

---

## 17. Security headers 🟢

Spring Security sets some headers by default, but for a public-facing auth system add these explicitly at the gateway:
- `Strict-Transport-Security` (HSTS) — forces HTTPS for all future requests
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy` — restricts what scripts/styles/frames a page can load; the single biggest defense against XSS actually stealing anything, even if some other code has a bug
- `Referrer-Policy: no-referrer` — specifically important on the password-reset page, so the reset token doesn't leak via the `Referer` header if the page links out anywhere

---

## 18. Optional stretch: MFA (TOTP) 🟢

Not required by the brief, but worth mentioning as a stretch goal in the design doc even if you don't fully build it — it's a strong thing to say you *considered*:
- TOTP (the Google-Authenticator-style 6-digit rotating code) is implementable in Spring Boot with a small library (e.g. `samstevens.totp`) — store a per-user secret (encrypted), generate a QR code for enrollment, verify the 6-digit code at login.
- If you don't build it, a one-paragraph ADR saying "we designed the login flow to support an MFA step later, but didn't implement it given the timeline" is a legitimate, honest way to show you know it exists without taking on the extra build risk.

---

## 19. Secrets management 🟢

- Local/demo: environment variables + `.env` (never committed; `.env.example` with placeholder values committed instead).
- The JWT signing key itself: generate an RSA keypair once, keep the private key out of the repo entirely (env var or mounted file), and only the public half ever gets published via your JWKS endpoint.
- If you do the Kubernetes bonus: move these into **Kubernetes Secrets** instead of plain ConfigMaps, which is the whole reason that resource exists separately.

---

## 20. Audit logging — what "enterprise" actually means here 🟢

An audit log isn't just "log everything" — it's a specific, append-only record of **security-relevant events**, structured so an admin (or you, in the viva) can answer "who did this, and when":

| Event | Fields to capture |
|---|---|
| `LOGIN_SUCCESS` / `LOGIN_FAILED` | user_id (if known), timestamp, IP, masked user-agent |
| `TOKEN_REUSE_DETECTED` | family_id, user_id, timestamp — flagged as high severity |
| `MERCHANT_APPROVED` / `MERCHANT_REJECTED` | admin_id, merchant_id, timestamp |
| `ROLE_CHANGED` | admin_id, target_user_id, old_role, new_role |
| `ACCOUNT_LOCKED` | user_id, timestamp, trigger (too many failed attempts) |

Treat this table as **append-only** (no updates or deletes from application code) — that's what makes it trustworthy as an audit trail rather than just another log table.

---

## 21. Dependency and vulnerability scanning 🟢

Since this module handles the most security-sensitive code in the whole system, it's worth running (even just for this module, if the team-wide CI isn't ready yet):
- **OWASP Dependency-Check** or **Trivy** against your own `pom.xml` — catches a known-vulnerable version of Spring Security or Nimbus before it ships.
- **CodeQL** (free on GitHub for public/student repos) — static analysis that catches some of the exact JWT pitfalls from section 7 (e.g. accepting `alg: none`) automatically.

---

## 22. Updated reference checklist (combining everything above)

- [ ] Argon2id hashing, tuned (~250ms/hash)
- [ ] Password length 8–64 accepted, no forced complexity, no forced rotation, breach-list check on signup/change
- [ ] RS256-only JWT verification, algorithm allow-list enforced
- [ ] Refresh token rotation + reuse detection + family revocation
- [ ] JWKS published, cached by consumers, old+new key overlap on rotation
- [ ] Exponential-backoff lockout, not permanent lockout
- [ ] Identical error + timing for wrong-password / locked / nonexistent account
- [ ] Forgot-password: single-use, short-lived, hashed token; same anti-enumeration rule; revokes sessions on reset
- [ ] CSRF: on (cookie-based) at the gateway, off for bearer-token-only internal APIs
- [ ] HttpOnly + Secure + SameSite cookies
- [ ] HSTS, CSP, X-Content-Type-Options, Referrer-Policy headers at the gateway
- [ ] Audit log: append-only, structured, covers the 5 event types above
- [ ] Secrets via env vars/K8s Secrets, never committed; JWT private key never leaves the service
- [ ] Dependency scan (Trivy/OWASP Dependency-Check) + CodeQL in CI
- [ ] (Stretch) MFA/TOTP designed for, even if not fully implemented

---

## Sources
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [Exponential Backoff Lockout: Stopping Brute Force Without Leaking Account Existence](https://www.web-developpeur.com/en/blog/lockout-exponential-backoff-enumeration)
- [NIST SP 800-63B password guidelines explained](https://netwrix.com/en/resources/blog/nist-password-guidelines/)
- [Spring Security 7.0: CSRF protection reference](https://docs.spring.io/spring-security/reference/7.0/servlet/exploits/csrf.html)
- [How to Handle JWT in Java for Enterprise Authentication](https://securityboulevard.com/2026/05/how-to-handle-jwt-in-java-for-enterprise-authentication-validation-rotation-and-pitfalls/)
- [Secure Password Storage Best Practices with Modern Hashing Algorithms](https://guptadeepak.com/secure-password-storage-best-practices-with-modern-hashing-algorithms/)
- [OAuth Refresh Token Rotation and Replay Detection Strategies](https://gravitee.io/corpus/gen-1403/oauth/oauth-refresh-token-rotation-and-replay-detection-strategies.html)
- [Spring Boot OAuth2 Authentication and Authorization in Practice (2026)](https://thelinuxcode.com/spring-boot-oauth2-authentication-and-authorization-in-practice-2026/)
- [How to Implement Rate Limiting with Bucket4j in Spring Boot](https://oneuptime.com/blog/post/2026-01-25-rate-limiting-bucket4j-spring-boot/view)
