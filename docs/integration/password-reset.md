# Forgot password (identity step 11a): contract for the frontends

Status: designed and approved, being built. The API below is the agreed contract, so frontends can start the pages.

## 1. "Forgot password?" page
```
POST /api/v1/auth/password-reset
Content-Type: application/json

{"email": "person@example.com"}
```
- Always answers `202` with the same body, whether or not the email has an account. Show: "If an account exists
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

{"token": "<from the fragment>", "newPassword": "<new password>", "mfaCode": "<6 digits, only if asked>"}
```
- `204` → done. Every session of the account has ended. Send the person to the login page (no automatic login).
- `400 INVALID_RESET_LINK` → the link is wrong, used or expired: offer "send a new link".
- `400 WEAK_PASSWORD` → same rules as sign-up (at least 15 characters, not in a known data breach).
- `400 MFA_CODE_REQUIRED` → the account has two-step login on (after step 11b): show a code field and send again
  with `mfaCode`.

## 4. What else happens
- The owner gets a "your password was reset" email.
- SwiftDrop receives the usual `credential-change` identity event.
- The reset is written to the audit log.
- Accounts that only use Google login can use this flow to add a password.
