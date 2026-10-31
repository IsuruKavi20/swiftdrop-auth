-- Failed-login counting (Step 14 review): failures older than an hour no longer count, so old typos fade away.
ALTER TABLE users ADD COLUMN last_failed_login_at TIMESTAMPTZ;
