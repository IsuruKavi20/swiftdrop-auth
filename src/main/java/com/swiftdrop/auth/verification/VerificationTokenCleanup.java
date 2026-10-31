package com.swiftdrop.auth.verification;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;

/** Removes tokens that expired more than a day ago, so the table doesn't grow forever. Safe to run on every instance. */
@Component
class VerificationTokenCleanup {

    private static final Duration KEEP_AFTER_EXPIRY = Duration.ofDays(1);

    private final VerificationTokenRepository tokens;
    private final Clock clock;

    VerificationTokenCleanup(VerificationTokenRepository tokens, Clock clock) {
        this.tokens = tokens;
        this.clock = clock;
    }

    @Scheduled(cron = "${swiftdrop.verification.cleanup-cron:0 0 3 * * *}")
    @Transactional
    public void deleteExpiredTokens() {
        tokens.deleteExpiredBefore(clock.instant().minus(KEEP_AFTER_EXPIRY));
    }
}
