package com.swiftdrop.auth.login;

import com.swiftdrop.auth.user.UserRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * The short database part of a successful login. Direct UPDATE statements (not load-modify-save), so two
 * logins of the same user at the same moment don't collide on the optimistic-locking version.
 */
@Component
class LoginRecorder {

    // Progressive, short, temporary: slows guessing a lot, but a stranger can delay a real user by 15 min at most
    private static final Duration SHORT_LOCK = Duration.ofMinutes(1);
    private static final Duration MEDIUM_LOCK = Duration.ofMinutes(5);
    private static final Duration LONG_LOCK = Duration.ofMinutes(15);
    private static final Duration FORGET_FAILURES_AFTER = Duration.ofHours(1);

    private final UserRepository users;

    LoginRecorder(UserRepository users) {
        this.users = users;
    }

    /** A wrong password for an existing account. Existing sessions are untouched (Step 11). */
    @Transactional
    public void recordFailedLogin(UUID userId, Instant now) {
        users.recordFailedLogin(userId, now, now.minus(FORGET_FAILURES_AFTER),
                now.plus(SHORT_LOCK), now.plus(MEDIUM_LOCK), now.plus(LONG_LOCK));
    }

    @Transactional
    public void recordSuccessfulLogin(UUID userId, Instant now, String currentHash, String upgradedHashOrNull) {
        users.updateLastLoginAt(userId, now);
        if (upgradedHashOrNull != null) {
            // Only replaces the hash we actually checked: a password changed meanwhile is never overwritten
            users.replacePasswordHash(userId, currentHash, upgradedHashOrNull, now);
        }
    }
}
