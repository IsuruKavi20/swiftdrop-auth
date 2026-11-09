-- Identity step 8: erasure everywhere (plan/STEP8-ERASURE.md).

-- Each receiver (e.g. SwiftDrop's backend) confirms it erased its copy of a deleted person. Ids and a time only.
CREATE TABLE erasure_confirmations (
    user_id      UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    receiver_id  VARCHAR(40)  NOT NULL,
    confirmed_at TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (user_id, receiver_id)
);

-- What is left after the hard delete: the id and dates, no personal data. Kept 60 days (longer than backups: 28) so
-- erasures can be applied again after restoring a backup (deploy/oke/reapply-erasures.ps1).
CREATE TABLE erasure_log (
    user_id    UUID         PRIMARY KEY,
    deleted_at TIMESTAMPTZ  NOT NULL,
    erased_at  TIMESTAMPTZ  NOT NULL,
    complete   BOOLEAN      NOT NULL     -- true: every receiver confirmed; false: finished by the 30-day limit
);

CREATE INDEX ix_erasure_log_erased_at ON erasure_log (erased_at);
-- The nightly job looks only at tombstones
CREATE INDEX ix_users_deleted_at ON users (deleted_at) WHERE status = 'DELETED';
