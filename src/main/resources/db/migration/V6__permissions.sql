-- Permissions: what a role may do. Code checks permissions (e.g. parcel:assign), never role names,
-- so "who may do what" is changed here, in data. Draft vocabulary, to be agreed with the other modules.
CREATE TABLE permissions (
    id   SMALLINT PRIMARY KEY,
    name VARCHAR(60) NOT NULL UNIQUE
        CHECK (name ~ '^[a-z]+:[a-z-]+$')
);

CREATE TABLE role_permissions (
    role_id       SMALLINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id SMALLINT NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

INSERT INTO permissions (id, name) VALUES
    (1, 'parcel:create'),
    (2, 'parcel:read-own'),
    (3, 'parcel:read-all'),
    (4, 'parcel:assign'),
    (5, 'delivery:read-own'),
    (6, 'delivery:update-status'),
    (7, 'delivery:read-all'),
    (8, 'merchant:api-access'),
    (9, 'merchant:approve'),
    (10, 'user:read'),
    (11, 'user:manage-roles'),
    (12, 'audit:read');

-- roles: 1 CUSTOMER, 2 MERCHANT, 3 COURIER, 4 DISPATCHER, 5 ADMIN (seeded in V1)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    (1, 1), (1, 2),                                   -- CUSTOMER
    (2, 1), (2, 2), (2, 8),                           -- MERCHANT
    (3, 5), (3, 6),                                   -- COURIER
    (4, 3), (4, 4), (4, 7),                           -- DISPATCHER
    (5, 3), (5, 4), (5, 7), (5, 9), (5, 10), (5, 11), (5, 12);  -- ADMIN
