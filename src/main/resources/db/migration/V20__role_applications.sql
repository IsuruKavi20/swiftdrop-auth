-- Identity step 7: applying for the COURIER or DISPATCHER role, decided by someone allowed to approve that role.

-- Who may approve what (least privilege): couriers by ADMIN or DISPATCHER, dispatchers by ADMIN only
INSERT INTO permissions (id, name) VALUES
    (13, 'role:approve-courier'),
    (14, 'role:approve-dispatcher');
INSERT INTO role_permissions (role_id, permission_id) VALUES
    (4, 13),             -- DISPATCHER approves couriers
    (5, 13), (5, 14);    -- ADMIN approves both

CREATE TABLE role_applications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role            VARCHAR(20)  NOT NULL,
    status          VARCHAR(10)  NOT NULL DEFAULT 'PENDING',
    note            VARCHAR(500),
    decided_by      UUID,                       -- the approver, or the applicant for a withdrawal
    decided_at      TIMESTAMPTZ,
    decision_reason VARCHAR(500),
    created_at      TIMESTAMPTZ  NOT NULL,
    CONSTRAINT ck_role_applications_role CHECK (role IN ('COURIER', 'DISPATCHER')),
    CONSTRAINT ck_role_applications_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'WITHDRAWN')),
    -- An open application has no decision; a closed one always says who and when
    CONSTRAINT ck_role_applications_decided CHECK
        ((status = 'PENDING') = (decided_at IS NULL) AND (decided_at IS NULL) = (decided_by IS NULL))
);

-- One open application per person and role: enforced by the database, also under concurrency
CREATE UNIQUE INDEX uk_role_applications_open ON role_applications (user_id, role) WHERE status = 'PENDING';
-- The approvers' list: open applications of a role, oldest first
CREATE INDEX ix_role_applications_queue ON role_applications (status, role, created_at);
