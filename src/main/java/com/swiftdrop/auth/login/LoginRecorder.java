package com.swiftdrop.auth.login;

import com.swiftdrop.auth.user.UserRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * The short database part of a successful login. Direct UPDATE statements (not load-modify-save), so two
 * logins of the same user at the same moment don't collide on the optimistic-locking version.
 */
@Component
class LoginRecorder {

    private final UserRepository users;

    LoginRecorder(UserRepository users) {
        this.users = users;
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
