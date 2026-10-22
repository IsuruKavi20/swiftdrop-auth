-- Users of the system (customers, merchants, couriers, dispatchers, admins)
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(320) NOT NULL,
    password_hash VARCHAR(255),
    status        VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE'
                  CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uk_users_email ON users (lower(email));

-- The five roles from the brief
CREATE TABLE roles (
    id   SMALLINT PRIMARY KEY,
    name VARCHAR(30) NOT NULL UNIQUE
);
INSERT INTO roles (id, name) VALUES
    (1, 'CUSTOMER'), (2, 'MERCHANT'), (3, 'COURIER'), (4, 'DISPATCHER'), (5, 'ADMIN');

-- Which user has which role (many-to-many)
CREATE TABLE user_roles (
    user_id UUID     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id SMALLINT NOT NULL REFERENCES roles (id),
    PRIMARY KEY (user_id, role_id)
);

-- Links a Google account to one of our users
CREATE TABLE oauth_accounts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider         VARCHAR(30)  NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_user_id)
);
