package com.swiftdrop.auth.account;

import com.swiftdrop.auth.audit.Actor;
import com.swiftdrop.auth.audit.AuditEntry;
import com.swiftdrop.auth.audit.AuditLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.Map;
import java.util.UUID;

/**
 * Identity step 8, saga step 5: a receiver (e.g. SwiftDrop's backend) tells us it erased its copy of a deleted
 * person. Ids and a time only. Repeats are fine, also after the hard delete (receivers retry).
 */
@Service
public class ErasureConfirmations {

    private static final Logger log = LoggerFactory.getLogger(ErasureConfirmations.class);

    private final JdbcTemplate jdbc;
    private final Clock clock;

    private final AuditLog audit;

    ErasureConfirmations(JdbcTemplate jdbc, Clock clock, AuditLog audit) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.audit = audit;
    }

    /** @throws ErasureNotFoundException the id is not a deleted account (unknown, or a living person) */
    @Transactional
    public void confirm(String receiverId, UUID userId) {
        Boolean finished = jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM identity.erasure_log WHERE user_id = ?)", Boolean.class, userId);
        if (Boolean.TRUE.equals(finished)) {
            return;   // already hard-deleted: a late retry, nothing left to do
        }
        int recorded = jdbc.update("INSERT INTO identity.erasure_confirmations (user_id, receiver_id, confirmed_at)"
                        + " SELECT id, ?, ? FROM identity.users WHERE id = ? AND status = 'DELETED'"
                        + " ON CONFLICT (user_id, receiver_id) DO NOTHING",
                receiverId, Timestamp.from(clock.instant()), userId);
        if (recorded == 0 && !alreadyConfirmed(receiverId, userId)) {
            throw new ErasureNotFoundException();
        }
        if (recorded == 1) {
            audit.record(AuditEntry.onUser(Actor.service("svc_" + receiverId), "erasure.confirmed", userId,
                    Map.of("receiver", receiverId)));
        }
        log.info("Erasure confirmed user={} receiver={}", userId, receiverId);
    }

    private boolean alreadyConfirmed(String receiverId, UUID userId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM identity.erasure_confirmations"
                + " WHERE user_id = ? AND receiver_id = ?)", Boolean.class, userId, receiverId));
    }
}
