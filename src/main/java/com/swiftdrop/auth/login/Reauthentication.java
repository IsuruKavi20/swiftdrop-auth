package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.security.Passwords;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * "Prove it's still you" before a sensitive change (email, password): the current password, checked exactly like
 * a login. A wrong password counts toward the same lockout, so a stolen access token can't be used to guess the
 * password here, and an active lockout blocks this check too (OWASP ASVS: re-authenticate for sensitive changes).
 */
@Component
public class Reauthentication {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final Bulkhead passwordWork;
    private final LoginRecorder recorder;
    private final Clock clock;

    Reauthentication(UserRepository users, PasswordEncoder encoder, Bulkhead passwordWork, LoginRecorder recorder,
                     Clock clock) {
        this.users = users;
        this.encoder = encoder;
        this.passwordWork = passwordWork;
        this.recorder = recorder;
        this.clock = clock;
    }

    /**
     * @throws ReauthenticationRequiredException the account has no password (Google-only) to check
     * @throws ReauthenticationFailedException   wrong password, or the account is locked or not usable
     */
    public void requireCurrentPassword(UUID userId, String rawPassword) {
        User user = users.findById(userId).orElseThrow(ReauthenticationFailedException::new);
        String hash = user.getPasswordHash();
        if (hash == null) {
            throw new ReauthenticationRequiredException();
        }
        String password = Passwords.normalise(rawPassword == null ? "" : rawPassword);
        // Argon2 (64 MB): the same small pool as login and signup
        boolean correct = passwordWork.call(() -> matches(password, hash));
        Instant now = clock.instant();
        if (!correct) {
            recorder.recordFailedLogin(userId, now);
            throw new ReauthenticationFailedException();
        }
        if (!user.isActiveAt(now)) {
            throw new ReauthenticationFailedException();
        }
    }

    // A stored hash with an unknown {id} prefix must not become a 500: it simply doesn't match
    private boolean matches(String password, String hash) {
        try {
            return encoder.matches(password, hash);
        } catch (IllegalArgumentException unreadableHash) {
            return false;
        }
    }
}
