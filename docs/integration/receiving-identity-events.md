# Receiving SwiftDrop identity events

Specification for the SwiftDrop `identity` module (owned by the auth owner; other modules only react to its internal
events such as `UserDeleted`). The auth service tells you when a person changes: registered,
profile, email, roles, password, sessions ended, deleted. Use it to keep `app_users` correct within seconds.

## 1. What you receive
Each event is a **Security Event Token** (RFC 8417): a JWT signed by the auth service.
```
header: { "alg": "RS256", "typ": "secevent+jwt", "kid": "<key id>" }
claims: {
  "iss": "https://auth.getswiftdrop.me", "aud": "swiftdrop-backend",
  "jti": "<event id>", "iat": <signed at>, "toe": <when it happened>,
  "sub_id": { "format": "opaque", "id": "<user id = the sub of their access tokens>" },
  "events": { "<event type URI>": { <what changed> } },
  "swiftdrop_version": 7
}
```
| Event type URI | Data | Do |
|---|---|---|
| `https://schemas.swiftdrop.me/secevent/identity/user-registered` | name, given/family name, picture, locale, email, email_verified, roles, status | create/update the row |
| `https://schemas.swiftdrop.me/secevent/identity/profile-updated` | name, given/family name, picture, locale | update profile fields |
| `https://schemas.swiftdrop.me/secevent/identity/roles-changed` | roles (the full new list) | replace roles; react (e.g. courier lost COURIER → unassign) |
| `https://schemas.openid.net/secevent/risc/event-type/identifier-changed` | `new-value` (new email) | update email (only if you store it) |
| `https://schemas.openid.net/secevent/caep/event-type/credential-change` | credential_type, change_type | optional: log / notify |
| `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | reason | optional: end your own server-side state |
| `https://schemas.openid.net/secevent/risc/event-type/account-disabled` / `account-enabled` | — | set status (emitted once admin blocking exists) |
| `https://schemas.openid.net/secevent/risc/event-type/account-purged` | — (nothing personal) | anonymise the person everywhere |

## 2. How to verify (every time, before using anything)
1. Parse the JWT; header `typ` must be **`secevent+jwt`**, `alg` **RS256**.
2. Verify the signature with the auth service's JWKS (`<issuer>/.well-known/jwks.json`, the same keys you use for
   access tokens; match `kid`).
3. `iss` = the auth issuer exactly; `aud` contains **your** receiver audience (`swiftdrop-backend`).
4. It must have `jti`, `events` (exactly one entry) and `sub_id.id`. There is **no `exp`** (a SET states a fact).
5. **Never accept a SET as a login token**, and never accept an access token as a SET (the `typ` differs).

## 3. Apply safely (retries, duplicates, wrong order)
- **Idempotent:** store processed `jti`s (e.g. 7 days); a `jti` already seen → answer success, do nothing.
- **Ordered per person:** keep the last `swiftdrop_version` per user (`app_users.last_event_version`). Apply only if
  the new version is higher; otherwise answer success and ignore it (it's older than what you have).
- Do it in one transaction: check version → update row → remember `jti`.

## 4. Push: we call you (RFC 8935)
`POST <your push URL>` with `Content-Type: application/secevent+jwt`, body = the SET.
- Answer **202** when stored/applied (also for repeats and old versions).
- Answer **400** with `{"err":"invalid_request","description":"..."}` only if the SET is invalid (bad signature,
  wrong audience...). We will never resend that one.
- Any other answer or a timeout (> 10 s) → we retry: 2 s, 4 s, 8 s ... up to every 10 min, for 24 h.
- Protect the endpoint: it accepts only verified SETs, so it needs no login, but rate-limit it and keep it off
  public docs. We don't follow redirects.

## 5. Poll: you call us (RFC 8936), for catch-up
Get a token as your service client (`svc_swiftdrop-backend`, permission `events:read`, client credentials at
`<issuer>/oauth2/token`), then:
```
POST <issuer>/api/v1/events/poll
{ "ack": ["<jti>", ...], "setErrs": { "<jti>": { "err": "invalid_request" } }, "maxEvents": 50 }
→ { "sets": { "<jti>": "<SET>", ... }, "moreAvailable": true }
```
Verify and apply each SET as above, then `ack` them in the next poll. Repeat while `moreAvailable`. Events whose
push we gave up on are still returned here. `maxEvents` ≤ 100; long polling is not offered.

## 6. What to configure
Ask the auth owner to register your receiver (`swiftdrop.events.receivers`: id `swiftdrop-backend`, audience
`swiftdrop-backend`, https push URL) and, for polling, the service client `svc_swiftdrop-backend` with
`events:read`. Secrets come from your environment, never git.

Background: `docs/adr/0001-identity-events-as-signed-security-event-tokens.md`, lesson 25.
