-- Identity step 3 review: wrong passwords on sensitive actions (email/password change, deletion) get their OWN
-- counter. Feeding the login lockout would let a thief with a stolen access token lock the owner out of logging in.
ALTER TABLE users
    ADD COLUMN reauth_failure_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN reauth_locked_until  TIMESTAMPTZ,
    ADD CONSTRAINT ck_users_reauth_failure_count CHECK (reauth_failure_count >= 0);
