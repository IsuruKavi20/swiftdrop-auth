package com.swiftdrop.auth.user;

public enum UserStatus {
    ACTIVE,
    LOCKED,
    DISABLED,
    /** The owner deleted the account: a tombstone (id only) until the erasure finishes (identity steps 3e, 8). */
    DELETED
}
