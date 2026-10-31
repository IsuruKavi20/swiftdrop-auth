package com.swiftdrop.auth.session;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;

/** Removes sessions that ended more than a day ago, so the table doesn't grow forever. Safe on every instance. */
@Component
class SessionCleanup {

    private static final Duration KEEP_AFTER_END = Duration.ofDays(1);

    private final RefreshTokenRepository tokens;
    private final Clock clock;

    SessionCleanup(RefreshTokenRepository tokens, Clock clock) {
        this.tokens = tokens;
        this.clock = clock;
    }

    @Scheduled(cron = "${swiftdrop.session.cleanup-cron:0 30 3 * * *}")
    @Transactional
    public void deleteEndedSessions() {
        tokens.deleteSessionsEndedBefore(clock.instant().minus(KEEP_AFTER_END));
    }
}
