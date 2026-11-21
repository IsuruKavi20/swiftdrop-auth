package com.swiftdrop.auth.account;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;

/** Removes reset links that expired more than a day ago (the flood limit only looks back one day). */
@Component
class PasswordResetCleanup {

    private static final Duration KEEP_AFTER_EXPIRY = Duration.ofDays(1);

    private final PasswordResetTokenRepository tokens;
    private final Clock clock;

    PasswordResetCleanup(PasswordResetTokenRepository tokens, Clock clock) {
        this.tokens = tokens;
        this.clock = clock;
    }

    @Scheduled(cron = "${swiftdrop.password-reset.cleanup-cron:0 10 3 * * *}")
    @Transactional
    public void deleteExpiredTokens() {
        tokens.deleteExpiredBefore(clock.instant().minus(KEEP_AFTER_EXPIRY));
    }
}
