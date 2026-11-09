# Admin screens for the SwiftDrop admin portal

Auth has **no screens of its own**. SwiftDrop's admin portal calls these APIs **directly from the browser with the
signed-in admin's own access token** (never through a SwiftDrop backend login), so auth checks that admin's
permissions and the audit log records that admin by name (id). Base URL: the auth issuer
(`https://auth.getswiftdrop.me`). Errors are RFC 9457 Problem Details; use the `code` field.

Show a page or button only if the token's `entitlements` contain its permission. Hiding buttons is only for
convenience: the server checks every rule again.

## 1. Find a person (`user:read`)
- By email (exact, case-insensitive): `GET /api/v1/admin/users?email=…` → `{ id, email, emailVerified, status, roles }`.
- By id: `GET /api/v1/admin/users/{id}` →
  `{ id, email, emailVerified, status, roles, createdAt, lastLoginAt, googleLinked, activeSessions }`.
- There is deliberately **no "list everyone"** (privacy). `USER_NOT_FOUND` (404) also for deleted people.
- `status`: `ACTIVE`, `DISABLED` (blocked), `LOCKED`.

## 2. Actions on a person
Every action needs a **reason** box: 3-200 characters, **no email addresses** (it goes into the audit log).
Ask "Are you sure?" before Block and Delete.

| Button | Call | Permission | Result |
|---|---|---|---|
| Block | `POST /api/v1/admin/users/{id}/block` `{ "reason": "…" }` | `user:manage-status` | `200` person detail; every session ends, SwiftDrop gets `account-disabled` |
| Unblock | `POST /api/v1/admin/users/{id}/unblock` `{ "reason": "…" }` | `user:manage-status` | `200` person detail; `account-enabled` |
| Log out everywhere | `POST /api/v1/admin/users/{id}/sessions/end` `{ "reason": "…" }` | `user:manage-status` | `200` person detail (`activeSessions: 0`) |
| Delete | `DELETE /api/v1/admin/users/{id}` `{ "reason": "…" }` | `user:delete` | `204`; the step 8 erasure starts (SwiftDrop gets `account-purged`, deletes its copy, confirms) |
| Give role | `PUT /api/v1/admin/users/{id}/roles/{role}` | `user:manage-roles` | `200`; not `MERCHANT` (merchant approval has its own flow) |
| Remove role | `DELETE /api/v1/admin/users/{id}/roles/{role}` | `user:manage-roles` | `200`; the person's sessions end |

Errors to show in plain words:
- `CANNOT_ACT_ON_SELF` (403): admins can't block or delete themselves.
- `LAST_ADMIN` (409): this would leave no active administrator.
- `VALIDATION_FAILED` (400): reason missing, too short or long, or contains an email address.
- `USER_NOT_FOUND` (404), `403`: no permission.
- Already blocked / already unblocked: not an error, the call changes nothing.

Blocked people keep a valid access token for at most 15 minutes; their refresh tokens stop working at once.

## 3. Access review (`user:read`)
`GET /api/v1/admin/access-review` → `[{ userId, role, grantedBy, grantedAt }]` for everyone holding ADMIN,
DISPATCHER or MERCHANT. `grantedBy` is the admin's id (or `break-glass`); null for grants made before the audit log
existed. Use it for a monthly "does everyone here still need this?" check.

## 4. Audit log (`audit:read`)
- Search: `GET /api/v1/admin/audit?actor=&target=&action=&from=&to=&before=&count=` (all optional; `count` 1-100,
  default 50) → newest first:
  `[{ seq, at, actorType, actorId, action, targetType, targetId, ip, requestId, details }]`.
  Next page: pass the last row's `seq` as `before`. `from`/`to` are ISO-8601 instants (`2026-11-01T00:00:00Z`).
- Export: `GET /api/v1/admin/audit/export?from=…&to=…` → a CSV download (at most 10 000 rows). The export itself is
  recorded in the audit log.
- Check: `GET /api/v1/admin/audit/verify` → `{ ok, rowsChecked, firstBrokenSeq, lastSeq, lastHash }`. Show a red
  warning if `ok` is false: someone changed the history.
- `actorType`: `USER` (an admin or the person themselves), `SERVICE` (e.g. `svc_swiftdrop-backend`), `SYSTEM`
  (scheduled jobs), `BREAK_GLASS` (the emergency tool).
- Actions: `role.granted`, `role.revoked`, `role-application.withdrawn`, `role-application.decided`,
  `merchant.decided`, `merchant.status-changed`, `user.blocked`, `user.unblocked`, `sessions.ended`,
  `account.deleted`, `erasure.confirmed`, `erasure.completed`, `email-change.requested`, `email-change.confirmed`,
  `email-change.undone`, `password.changed`, `directory.email-read`, `audit.exported`.
- Escape every value when displaying (`details.reason` is text an admin typed).

## 5. When the portal is down
Operators with cluster access use `deploy/oke/break-glass.ps1` (a menu with the same actions and rules), recorded as
`BREAK_GLASS` in the audit log.
