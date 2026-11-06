package com.swiftdrop.auth.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;

/**
 * Identity events are kept for {@code swiftdrop.events.retention} (30 days), then deleted with their delivery rows:
 * personal data is not kept longer than needed, and the tables don't grow for ever. A receiver that was down longer
 * than that rebuilds from the Directory API.
 */
@Component
public class IdentityEventRetention {

    private static final Logger log = LoggerFactory.getLogger(IdentityEventRetention.class);

    private final JdbcTemplate jdbc;
    private final Duration retention;
    private final Clock clock;

    IdentityEventRetention(JdbcTemplate jdbc, @Value("${swiftdrop.events.retention:30d}") Duration retention,
                           Clock clock) {
        this.jdbc = jdbc;
        this.retention = retention;
        this.clock = clock;
    }

    @Scheduled(cron = "${swiftdrop.events.retention-cron:0 15 4 * * *}")
    public int deleteExpired() {
        int deleted = jdbc.update("DELETE FROM identity.identity_events WHERE occurred_at < ?",
                Timestamp.from(clock.instant().minus(retention)));
        log.info("Identity events older than {} deleted: {}", retention, deleted);
        return deleted;
    }
}
