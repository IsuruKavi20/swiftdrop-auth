# SwiftDrop Auth Service

Identity, access and authentication for **SwiftDrop**, a parcel delivery system (Module 1).
One small, carefully built service proves who a user is and what they may do, and gives them **signed tokens** that
every other SwiftDrop application verifies by itself with our public key.

```
 browser / mobile app ──login──► AUTH SERVICE ──access token──► app
        │                         (this repo)                    │ Authorization: Bearer <token>
        │                              │ public keys (JWKS)       ▼
        │                              └──────────────────► SwiftDrop backend(s) verify tokens locally
```

**Version 1.0.0** · Java 25 · Spring Boot 4.1 · Spring Security 7 · PostgreSQL 17 · Flyway · Docker · [Changelog](CHANGELOG.md)

---

## What it does
| Area | Features |
|---|---|
| Accounts | signup (always `202`, no enumeration), email verification, NIST password rules, breached-password check, Argon2id |
| Login | email + password, **Continue with Google** (OIDC + PKCE), progressive temporary lockout |
| Tokens | RS256 access tokens (15 min, `typ: at+jwt`), rotating refresh tokens with reuse detection, logout |
| Authorization | roles + permissions in tokens, ownership checks, admin role management |
| Merchants | application → admin approval → API credentials (OAuth 2.0 client credentials) |
| Protection | per-IP rate limits, CORS allow-list, request size limit, strict JSON, RFC 9457 error format |

## Using it from another SwiftDrop application
Read **[docs/integration/verifying-swiftdrop-tokens.md](docs/integration/verifying-swiftdrop-tokens.md)**: dependency,
config, copy-paste security configuration, how to get the user id and permissions, merchant tokens, test tokens,
frontend login/refresh/Google rules. Works the same for microservices or one monolith.

## Run it locally
Prerequisites: **JDK 25**, **Docker Desktop**.
```powershell
copy .env.example .env          # then fill in your own local passwords (and Google client, optional)
docker compose up -d            # PostgreSQL (port 5433) + Mailpit (8025)
.\mvnw spring-boot:run          # dev profile, http://localhost:9000
```
| URL | What |
|---|---|
| http://localhost:9000/swagger-ui.html | API documentation (dev only) |
| http://localhost:8025 | Mailpit: verification emails in development |
| http://localhost:9000/.well-known/jwks.json | public keys |
| `POST http://localhost:9000/api/v1/dev/test-tokens` | instant test tokens for teammates (dev only) |

## Main endpoints
| Method + path | Purpose |
|---|---|
| `POST /api/v1/auth/signup` · `POST /api/v1/auth/email-verification` · `…/resend` | create account, verify email |
| `POST /api/v1/auth/login` · `POST /api/v1/auth/refresh` · `POST /api/v1/auth/logout` | sessions |
| `GET /oauth2/authorization/google?code_challenge=…` · `POST /api/v1/auth/google/exchange` | Google login |
| `GET /api/v1/auth/me` | who am I (needs a token) |
| `GET /.well-known/jwks.json` | public signing keys |
| `/api/v1/admin/users/**` · `/api/v1/admin/merchants/**` | administration (permissions required) |
| `POST /api/v1/merchants/application` · `/api/v1/merchants/me/clients` · `POST /oauth2/token` | merchants |
| `GET /actuator/health` | health check for the platform |
Full contract: Swagger in development.

## Run the Docker image
```powershell
docker build -t swiftdrop-auth:1.0.0 .
```
To try the image locally the way production runs it (prod profile, port 9001, fake https URLs, your `.env`):
`.\docker\run-prod-image.ps1`, then `curl.exe http://localhost:9001/.well-known/jwks.json`; remove it with
`docker rm -f auth-local`.

The image runs as a non-root user on port **9000** and contains **no secrets**. It must be started with the
`prod` profile and these environment variables (it refuses to start if any required one is missing or unsafe):

| Variable | Meaning |
|---|---|
| `SPRING_PROFILES_ACTIVE=prod` | production settings (required; there is no default profile) |
| `DB_URL`, `DB_APP_USER`, `DB_APP_PASSWORD`, `DB_MIGRATOR_USER`, `DB_MIGRATOR_PASSWORD` | PostgreSQL (app user: rows only; migrator: schema changes) |
| `SWIFTDROP_JWT_ISSUER` | public https URL of this service, e.g. `https://auth.example.com` |
| `SWIFTDROP_JWT_PRIVATE_KEY_LOCATION` | path to the mounted RSA private key (PKCS#8 PEM) |
| `SWIFTDROP_PUBLIC_BASE_URL` | same public https URL (pins Google's redirect address) |
| `SWIFTDROP_FRONTEND_BASE_URL` | the frontend's https URL (email links, Google return) |
| `SWIFTDROP_CORS_ALLOWED_ORIGINS` | comma-separated frontend origins allowed to call the API from browsers |
| `SWIFTDROP_TRUSTED_PROXIES` | regex of the load balancer's addresses (the only ones allowed to set X-Forwarded-For) |
| `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD` | SMTP with TLS for verification emails |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | the production Google OAuth client |
| `SWIFTDROP_BOOTSTRAP_ADMIN_EMAIL` (optional) | a verified account to make the first admin; remove afterwards |

## Tests
```powershell
.\mvnw clean verify     # 346 tests: unit + integration against a real PostgreSQL (Testcontainers, needs Docker)
```
Includes the brief's required test (a courier cannot access another courier's deliveries), architecture rules
(ArchUnit, Spring Modulith) and a test for every security review finding.

## Project layout
```
src/main/java/com/swiftdrop/auth/
  common/     shared building blocks: errors, request id, limits, rate limiting, crypto
  security/   Spring Security setup, password hashing, CORS, authorization annotations
  user/  signup/  verification/  login/  token/  session/  google/  admin/  merchant/
src/main/resources/db/migration/   Flyway migrations V1–V10
docs/integration/                  guide for teams that use our tokens
```

## Known limitations (v1.0.0)
- Rate limits are kept in memory: right for one instance; several instances need Redis.
- No audit log, MFA or "forgot password" yet.
- Google login: the production Google client must be switched from Testing to In production.

## Security
Secrets never live in the code or the image: local values are in the git-ignored `.env` and `.secrets/`,
production values in the platform's encrypted environment variables. Report security problems privately to the
module owner rather than in a public issue.
