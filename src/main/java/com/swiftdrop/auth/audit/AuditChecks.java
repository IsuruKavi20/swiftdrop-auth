package com.swiftdrop.auth.audit;

import com.swiftdrop.auth.common.concurrency.WriteOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;

/**
 * Recomputes the chain (verify) and removes rows older than one year (retention). After a clean-up the chain starts
 * at the checkpoint: the seq and hash of the last removed row, so the first remaining row still links to something.
 */
@Service
public class AuditChecks {

    private static final Logger log = LoggerFactory.getLogger(AuditChecks.class);
    // One day more than the database trigger allows (365), so the two clocks never disagree
    private static final Duration KEEP = Duration.ofDays(366);

    private final JdbcTemplate jdbc;
    private final Clock clock;

    AuditChecks(JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public AuditVerification verify() {
        Map<String, Object> checkpoint = jdbc.queryForMap("SELECT seq, hash FROM identity.audit_checkpoint WHERE id = 1");
        Walk walk = new Walk(((Number) checkpoint.get("seq")).longValue(), (String) checkpoint.get("hash"));
        jdbc.query("SELECT * FROM identity.audit_log ORDER BY seq", walk::next);
        if (walk.broken != null) {
            log.error("Audit chain broken at seq={}", walk.broken);
        }
        return new AuditVerification(walk.broken == null, walk.rows, walk.broken, walk.lastSeq, walk.lastHash);
    }

    /** @return how many rows were removed */
    @Transactional
    @Scheduled(cron = "${swiftdrop.audit.retention-cron:0 15 4 * * *}")
    public int removeExpired() {
        WriteOrder.lock(jdbc);   // no new row is chained while the start of the chain moves
        Timestamp cutoff = Timestamp.from(clock.instant().minus(KEEP));
        // Only an unbroken run of old rows from the start: the checkpoint must be the row just before the rest
        Long upTo = jdbc.queryForObject("SELECT max(seq) FROM identity.audit_log WHERE at < ? AND seq < coalesce("
                + "(SELECT min(seq) FROM identity.audit_log WHERE at >= ?), 9223372036854775807)", Long.class,
                cutoff, cutoff);
        if (upTo == null) {
            return 0;
        }
        jdbc.update("UPDATE identity.audit_checkpoint SET seq = a.seq, hash = a.hash FROM identity.audit_log a"
                + " WHERE id = 1 AND a.seq = ?", upTo);
        int removed = jdbc.update("DELETE FROM identity.audit_log WHERE seq <= ?", upTo);
        log.info("Audit retention removed {} rows (checkpoint seq={})", removed, upTo);
        return removed;
    }

    /** Walks the rows in order, keeping the previous hash; remembers the first row that does not fit. */
    private static final class Walk {
        long rows;
        long lastSeq;
        String lastHash;
        Long broken;

        Walk(long startSeq, String startHash) {
            this.lastSeq = startSeq;
            this.lastHash = startHash;
        }

        void next(ResultSet rs) throws SQLException {
            rows++;
            long seq = rs.getLong("seq");
            AuditChain.Row row = new AuditChain.Row(seq, rs.getTimestamp("at").toInstant(), rs.getString("actor_type"),
                    rs.getString("actor_id"), rs.getString("action"), rs.getString("target_type"),
                    rs.getString("target_id"), rs.getString("ip"), rs.getString("request_id"), rs.getString("details"));
            String stored = rs.getString("hash");
            boolean fits = seq > lastSeq && lastHash.equals(rs.getString("prev_hash"))
                    && stored.equals(AuditChain.hash(lastHash, row));
            if (!fits && broken == null) {
                broken = seq;
            }
            lastSeq = seq;
            lastHash = stored;
        }
    }
}
