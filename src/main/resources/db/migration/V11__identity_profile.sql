-- Identity profile (USER-DATA-AND-IDENTITY.md, Tool A). OpenID Connect standard claim names.
-- All columns are nullable: accounts created before V11 have no profile yet.
-- Java (PersonName) is the main validation; these checks are the last line of defence for any other writer.
ALTER TABLE users
    -- 100 visible characters can be up to 300 code points (Sinhala/Tamil conjuncts); PersonName enforces 100
    ADD COLUMN name               VARCHAR(300),
    ADD COLUMN given_name         VARCHAR(300),
    ADD COLUMN family_name        VARCHAR(300),
    ADD COLUMN picture_url        VARCHAR(2048),
    -- BCP 47 language tag, e.g. si-LK (RFC 5646 recommends supporting at least 35 characters)
    ADD COLUMN locale             VARCHAR(35),
    -- Who wrote the profile last: USER edits are never overwritten by a later Google login
    ADD COLUMN profile_source     VARCHAR(10),
    -- Last profile change (users.updated_at also moves on logins, so it can't serve as OIDC updated_at)
    ADD COLUMN profile_updated_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_users_name_not_blank        CHECK (name IS NULL OR btrim(name) <> ''),
    ADD CONSTRAINT ck_users_given_name_not_blank  CHECK (given_name IS NULL OR btrim(given_name) <> ''),
    ADD CONSTRAINT ck_users_family_name_not_blank CHECK (family_name IS NULL OR btrim(family_name) <> ''),
    -- https only: no http (mixed content, tracking) and no javascript:/data: URLs in an <img src>
    ADD CONSTRAINT ck_users_picture_https         CHECK (picture_url IS NULL OR picture_url LIKE 'https://%'),
    ADD CONSTRAINT ck_users_profile_source        CHECK (profile_source IN ('USER', 'GOOGLE'));
