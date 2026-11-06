# Role applications: screens for the SwiftDrop frontend

The auth service stores and decides role applications; the **screens live in SwiftDrop's frontend** and call the
auth API with the signed-in person's own access token. Base URL: the auth issuer (e.g. `https://auth.getswiftdrop.me`).

## 1. "Become a courier / dispatcher" (any signed-in user)
- Apply: `POST /api/v1/me/role-applications` `{ "role": "COURIER" | "DISPATCHER", "note": "optional, ≤ 500 chars" }`
  → `201` with the application. Errors (RFC 9457 `code`): `ROLE_APPLICATION_EXISTS`, `ROLE_ALREADY_HELD`,
  `ROLE_CONFLICT` (courier and dispatcher can't be combined), `ROLE_REAPPLY_TOO_SOON` (7 days after a rejection).
- My applications: `GET /api/v1/me/role-applications` → list with `status` (PENDING, APPROVED, REJECTED, WITHDRAWN),
  `created_at`, `decided_at`, `decision_reason`.
- Withdraw: `DELETE /api/v1/me/role-applications/{id}` → `204` (only open ones; `ROLE_APPLICATION_CLOSED` otherwise).
- After approval the new role is in the access token from the next refresh (≤ 15 min), or log in again.
- Licence / vehicle / documents are collected by SwiftDrop's own courier screens (business data), not sent here.

## 2. "Applications to review" (admins; dispatchers for couriers)
Show this page only if the access token's `entitlements` contain `role:approve-courier` or `role:approve-dispatcher`.
- List: `GET /api/v1/admin/role-applications?status=PENDING&role=COURIER` (both optional; the server only returns
  roles the caller may decide) → `[{ id, role, status, note, applicant: { id, name }, created_at }]`, oldest first.
- Decide: `POST /api/v1/admin/role-applications/{id}/decision` `{ "decision": "APPROVE" | "REJECT", "reason": "…" }`.
  Show the reason box for rejections (the applicant sees it). Errors: `ROLE_SELF_DECISION` (own application),
  `ROLE_APPLICATION_CLOSED`, `ACCOUNT_NOT_ELIGIBLE`, `ROLE_CONFLICT`, `403` (role not decidable by this person).
- Every rule is enforced by the server; hiding buttons in the UI is only for convenience.
- Escape `note`, `reason` and `applicant.name` when displaying (they are user-typed text).
