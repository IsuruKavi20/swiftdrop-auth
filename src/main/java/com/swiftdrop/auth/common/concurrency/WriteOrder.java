package com.swiftdrop.auth.common.concurrency;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * One transaction-scoped Postgres lock shared by every ordered log (identity events, audit log): rows get their
 * numbers and COMMIT in the same order. One shared lock (not one per log) so two logs written in one transaction
 * can never deadlock each other. Taking it again in the same transaction is free (advisory locks are re-entrant).
 */
public final class WriteOrder {

    /** Any fixed number. */
    public static final long LOCK_ID = 6_017_001L;

    private WriteOrder() {
    }

    /** Waits for the lock; it is released by the transaction's commit or rollback. */
    public static void lock(JdbcTemplate jdbc) {
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)::text", String.class, LOCK_ID);
    }
}
