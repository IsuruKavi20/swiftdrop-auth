-- Identity step 6c: who must receive which identity event, and how delivery went.

-- One row per configured receiver: the newest diary line already queued for it
CREATE TABLE event_receivers (
    receiver_id    VARCHAR(40) PRIMARY KEY,
    enqueued_up_to BIGINT      NOT NULL,
    CONSTRAINT ck_event_receivers_id CHECK (receiver_id ~ '^[a-z0-9-]{3,40}$')
);

-- One row per (event, receiver)
CREATE TABLE event_deliveries (
    event_id        UUID         NOT NULL REFERENCES identity_events (id) ON DELETE CASCADE,
    receiver_id     VARCHAR(40)  NOT NULL REFERENCES event_receivers (receiver_id) ON DELETE CASCADE,
    seq             BIGINT       NOT NULL,                     -- copy of the event's order, to send oldest first
    status          VARCHAR(10)  NOT NULL DEFAULT 'PENDING',
    attempts        INTEGER      NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ  NOT NULL,                     -- also the 60-second "lease" while one pod sends
    created_at      TIMESTAMPTZ  NOT NULL,
    last_error      VARCHAR(200),
    finished_at     TIMESTAMPTZ,
    PRIMARY KEY (event_id, receiver_id),
    CONSTRAINT ck_event_deliveries_status CHECK (status IN ('PENDING', 'DELIVERED', 'DEAD')),
    CONSTRAINT ck_event_deliveries_attempts CHECK (attempts >= 0)
);

-- The sender's question: "which pending deliveries of this receiver are due?"
CREATE INDEX ix_event_deliveries_due ON event_deliveries (receiver_id, next_attempt_at) WHERE status = 'PENDING';
