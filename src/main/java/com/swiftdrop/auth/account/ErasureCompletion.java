package com.swiftdrop.auth.account;

import com.swiftdrop.auth.signals.EventsProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Identity step 8, saga step 5: finishes erasures. A deleted account (tombstone) is HARD-deleted once every
 * configured events receiver confirmed, or after 30 days at the latest. Database cascades remove every linked row
 * (sessions, login links, own role applications); decisions the person made as an approver keep only the bare id.
 * Leaves one line in erasure_log (id + dates) for 60 days, to re-apply erasures after a backup restore.
 * Safe on several pods at once (FOR UPDATE SKIP LOCKED: each tombstone is finished by exactly one of them).
 */
@Component
public class ErasureCompletion {

    static final Duration WAIT_AT_MOST = Duration.ofDays(30);
    static final Duration KEEP_LOG = Duration.ofDays(60);
    private static final int BATCH = 100;
    private static final Logger log = LoggerFactory.getLogger(ErasureCompletion.class);

    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final EventsProperties events;
    private final Clock clock;

    ErasureCompletion(JdbcTemplate jdbc, TransactionTemplate transactions, EventsProperties events, Clock clock) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.events = events;
        this.clock = clock;
    }

    @Scheduled(cron = "${swiftdrop.erasure.cron:0 0 4 * * *}")
    void scheduled() {
        int erased = completeDue();
        if (erased > 0) {
            log.info("Erasures completed count={}", erased);
        }
    }

    /** @return how many tombstones this run hard-deleted */
    public int completeDue() {
        Instant now = clock.instant();
        List<String> receivers = events.receivers().stream().map(EventsProperties.Receiver::id).toList();
        // Receiver ids match ^[a-z0-9-]{3,40}$ (checked at startup): this array literal can't carry an injection
        String receiverArray = "{" + String.join(",", receivers) + "}";
        Integer erased = transactions.execute(status -> {
            List<Map<String, Object>> due = jdbc.queryForList(
                    "SELECT u.id, u.deleted_at FROM identity.users u WHERE u.status = 'DELETED' AND (u.deleted_at < ?"
                            + " OR (SELECT count(*) FROM identity.erasure_confirmations c WHERE c.user_id = u.id"
                            + " AND c.receiver_id = ANY (?::varchar[])) = ?)"
                            + " ORDER BY u.deleted_at LIMIT ? FOR UPDATE OF u SKIP LOCKED",
                    Timestamp.from(now.minus(WAIT_AT_MOST)), receiverArray, receivers.size(), BATCH);
            due.forEach(row -> erase(row, receiverArray, receivers.size(), now));
            jdbc.update("DELETE FROM identity.erasure_log WHERE erased_at < ?", Timestamp.from(now.minus(KEEP_LOG)));
            return due.size();
        });
        return erased == null ? 0 : erased;
    }

    private void erase(Map<String, Object> tombstone, String receiverArray, int receiverCount, Instant now) {
        UUID id = (UUID) tombstone.get("id");
        Integer confirmed = jdbc.queryForObject("SELECT count(*) FROM identity.erasure_confirmations"
                + " WHERE user_id = ? AND receiver_id = ANY (?::varchar[])", Integer.class, id, receiverArray);
        boolean complete = confirmed != null && confirmed >= receiverCount;
        jdbc.update("INSERT INTO identity.erasure_log (user_id, deleted_at, erased_at, complete) VALUES (?, ?, ?, ?)"
                + " ON CONFLICT (user_id) DO NOTHING", id, tombstone.get("deleted_at"), Timestamp.from(now), complete);
        jdbc.update("DELETE FROM identity.users WHERE id = ?", id);
        if (complete) {
            log.info("Account erased everywhere user={}", id);
        } else {
            log.warn("Account erased after {} days without every receiver's confirmation user={}",
                    WAIT_AT_MOST.toDays(), id);
        }
    }
}
