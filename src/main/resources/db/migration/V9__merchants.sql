-- Merchants (Step 13): the identity side only. Shop details, addresses, pricing live in the merchant service.

CREATE TABLE merchants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    business_name       VARCHAR(120) NOT NULL,
    registration_number VARCHAR(50)  NOT NULL,
    website             VARCHAR(255),
    status              VARCHAR(20)  NOT NULL,
    decision_reason     VARCHAR(40),
    decided_by          UUID REFERENCES users (id) ON DELETE SET NULL,
    decided_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL,
    updated_at          TIMESTAMPTZ  NOT NULL,
    version             BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT uk_merchants_user UNIQUE (user_id),
    CONSTRAINT ck_merchants_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'SUSPENDED')),
    -- a decision has a time; a pending application has none
    CONSTRAINT ck_merchants_decided CHECK ((status = 'PENDING') = (decided_at IS NULL)),
    -- a rejection always says why, from a fixed list (no free text: no personal data, nothing to inject)
    CONSTRAINT ck_merchants_reason CHECK ((status = 'REJECTED') = (decision_reason IS NOT NULL)),
    CONSTRAINT ck_merchants_reason_values CHECK (decision_reason IS NULL OR decision_reason IN
        ('INCOMPLETE_INFORMATION', 'UNVERIFIABLE_BUSINESS', 'NOT_ELIGIBLE', 'OTHER')),
    CONSTRAINT ck_merchants_website CHECK (website IS NULL OR website ~ '^https://[^[:space:]]+$')
);

CREATE INDEX ix_merchants_status_created ON merchants (status, created_at);
-- One business = one merchant: a registration number can be approved (or suspended) only once
CREATE UNIQUE INDEX uk_merchants_registration_active ON merchants (registration_number)
    WHERE status IN ('APPROVED', 'SUSPENDED');

-- OAuth 2.0 clients for a merchant's own software (client credentials grant). Only the secret's SHA-256 is stored.
CREATE TABLE merchant_clients (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id  UUID        NOT NULL REFERENCES merchants (id) ON DELETE CASCADE,
    client_id    VARCHAR(25) NOT NULL,
    secret_hash  VARCHAR(64) NOT NULL,
    name         VARCHAR(60) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    CONSTRAINT uk_merchant_clients_client_id UNIQUE (client_id),
    CONSTRAINT ck_merchant_clients_client_id CHECK (client_id ~ '^mc_[A-Za-z0-9_-]{22}$'),
    CONSTRAINT ck_merchant_clients_secret_hex CHECK (secret_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX ix_merchant_clients_merchant_id ON merchant_clients (merchant_id);
