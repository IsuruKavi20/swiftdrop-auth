# Forgot password (identity step 11a): contract for the frontends

Status: built (identity step 11a). The MFA part of section 3 comes with step 11b.

## 1. "Forgot password?" page
```
POST /api/v1/auth/password-reset
Content-Type: application/json

{"email": "person@example.com"}
```
- Always answers `202` with the same body (`{"message": "..."}`), whether or not the email has an account. Show: "If an account exists
  for this email, we sent a link. Check your inbox."
- Rate limited per IP and per email (`429` when exceeded: show "try again in a minute").

## 2. The email link
`https://<your frontend>/reset-password#token=<token>`
- The token is in the URL **fragment** (`#`): browsers never send it to servers or in `Referer` headers.
- It works **once**, for **30 minutes**. Asking for a new link cancels the older ones.
- The page must NOT call the API on load (email scanners open links). Call it when the person presses the button.

## 3. "Choose a new password" page
```
POST /api/v1/auth/password-reset/confirm
Content-Type: application/json

{"token": "<from the fragment>", "new_password": "<new password>"}
```
- `204` → done. Every session of the account has ended. Send the person to the login page (no automatic login).
- `400 INVALID_OR_EXPIRED_TOKEN` → the link is wrong, used or expired: offer "send a new link".
- `400 WEAK_PASSWORD` → same rules as sign-up (at least 15 characters, not in a known data breach). The link
  still works: let the person try another password.
- (After step 11b) `400 MFA_CODE_REQUIRED` → the account has two-step login on: show a code field and send again
  with `mfa_code`.

## 4. What else happens
- The owner gets a "your password was reset" email.
- SwiftDrop receives the usual `credential-change` identity event.
- The reset is written to the audit log.
- Accounts that only use Google login can use this flow to add a password.
- A failed-password lock on the account is lifted (it guarded the old password).
- Blocked or deleted accounts get no email.
