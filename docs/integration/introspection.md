# Checking tokens for dangerous actions (introspection) and logging out properly (revocation)

For SwiftDrop's backend and frontends. Base URL: the auth issuer (`https://auth.getswiftdrop.me`). Both endpoints
are listed in `/.well-known/openid-configuration` (`introspection_endpoint`, `revocation_endpoint`).

## 1. Why
Access tokens are checked locally (signature + expiry) and live 15 minutes. If auth blocks someone, changes their
password or removes a role, their current token keeps passing a LOCAL check until it expires. For everyday pages
that's fine. For dangerous actions, ask auth first.

## 2. Which actions must introspect (backend)
- Payouts, refunds, anything that moves money.
- Admin actions done through SwiftDrop's own API (changing a delivery's owner, editing other people's data).
- Deleting data.
- Changing merchant settings (bank details, API keys).
- **Anything an AI assistant does for a user** (it acts with the user's token: if the user is blocked, it must stop
  at once).

Everything else: keep the local check (fast, works when auth is down).

## 3. How (backend, service client `svc_swiftdrop-backend`, permission `token:introspect`)
```
POST /oauth2/introspect
Authorization: Basic base64(svc_swiftdrop-backend:<client secret>)
Content-Type: application/x-www-form-urlencoded

token=<the user's access token>
```
Answers (always `200` for a known caller):
- `{"active": false}` → refuse the action with 401 (ask the user to log in again). No reason is given, on purpose.
- `{"active": true, "sub", "client_id", "token_type", "iss", "aud", "iat", "exp", "jti", "roles", "entitlements"}`;
  merchant machine tokens also have `"merchant_id"` and `"merchant_owner"` (the owner's user id)
  → use **these** `roles`/`entitlements` (they are the person's roles NOW, not when the token was made).

Errors: `401 invalid_client` (wrong id/secret), `403 unauthorized_client` (client lacks `token:introspect`),
`400 invalid_request` (no token).

Rules:
- Cache an answer for **at most 30 seconds**, keyed by the token's `jti`.
- If auth can't be reached or answers 5xx: **refuse the dangerous action** ("please try again in a minute").
  Never fall back to the local check for these actions.
- Never log the token itself.

Spring Boot: `spring.security.oauth2.resourceserver.opaquetoken.*` is for opaque-token APIs; for us call it
yourself (e.g. `RestClient`) only in the dangerous handlers, or use Spring's `SpringOpaqueTokenIntrospector`
with the URL and client credentials above.

## 4. Logout (frontends)
On "Log out", call BOTH:
1. `POST /api/v1/auth/logout` with the refresh token (as today), or `POST /oauth2/revoke` `token=<refresh token>`;
2. `POST /oauth2/revoke` (form) `token=<access token>&token_type_hint=access_token`.

Revoke always answers `200` (even for an unknown token) and needs no login: holding the token is enough.
Since step 10 each access token carries `sid` (its login session): revoking the refresh token alone already makes
that session's access tokens inactive for introspection; step 2 additionally cancels the single access token.
