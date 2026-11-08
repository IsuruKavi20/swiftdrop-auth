-- Identity step 6a: every change to a person becomes an event (later sent to SwiftDrop as a signed SET).
-- Written in the SAME transaction as the change: if the change commits the event exists, otherwise neither does.

-- Per-person counter: each event gets the next number, so a receiver can ignore older or repeated events.
-- Deliberately NOT mapped in the JPA entity: Hibernate never writes it back (no lost increments).
ALTER TABLE users ADD COLUMN identity_version BIGINT NOT NULL DEFAULT 0;

CREATE TABLE identity_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- becomes the SET's jti
    seq          BIGSERIAL    NOT NULL,                         -- global order for sending and polling
    -- No foreign key: the "account purged" event must outlive the person's row (hard delete, step 8)
    user_id      UUID         NOT NULL,
    user_version BIGINT       NOT NULL,
    event_type   VARCHAR(200) NOT NULL,
    payload      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    occurred_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uk_identity_events_seq UNIQUE (seq),
    CONSTRAINT uk_identity_events_user_version UNIQUE (user_id, user_version),
    CONSTRAINT ck_identity_events_version CHECK (user_version > 0),
    CONSTRAINT ck_identity_events_type CHECK (event_type LIKE 'https://%')
);
