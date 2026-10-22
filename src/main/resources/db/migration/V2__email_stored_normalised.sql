-- Emails are now stored normalised (trimmed, NFKC, lowercase) by the application.
-- Enforce that in the database too, and replace the lower(email) index with a plain
-- unique constraint so lookups by "email = ?" can use the index.
DROP INDEX uk_users_email;

ALTER TABLE users
    ADD CONSTRAINT ck_users_email_lowercase CHECK (email = lower(email)),
    ADD CONSTRAINT uk_users_email UNIQUE (email);
