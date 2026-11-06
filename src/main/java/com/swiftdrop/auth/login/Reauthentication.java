package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.security.Passwords;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * "Prove it's still you" before a sensitive change (email, password, deletion): the current password (OWASP ASVS).
 * Wrong passwords have their OWN counter: 5 pause sensitive actions for 15 minutes. They never feed the login
 * lockout, otherwise a thief with a stolen access token could lock the owner out of logging in.
 */
@Component
public class Reauthentication {

    static final int MAX_FAILURES = 5;
    static final Duration PAUSE = Duration.ofMinutes(15);

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final Bulkhead passwordWork;
    private final TransactionTemplate transactions;
    private final Clock clock;

    Reauthentication(UserRepository users, PasswordEncoder encoder, Bulkhead passwordWork,
                     TransactionTemplate transactions, Clock clock) {
        this.users = users;
        this.encoder = encoder;
        this.passwordWork = passwordWork;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * @throws BadCredentialsException           (401) the account no longer exists or is not active (deleted,
     *                                           disabled): the still-valid access token speaks for nobody
     * @throws ReauthenticationRequiredException the account has no password (Google-only) to check
     * @throws ReauthenticationFailedException   wrong password, sensitive actions paused, or login-locked
     */
    public void requireCurrentPassword(UUID userId, String rawPassword) {
        User user = users.findById(userId).filter(User::isUsable)
                .orElseThrow(() -> new BadCredentialsException("Account not active"));
        Instant now = clock.instant();
        Instant pausedUntil = user.getReauthLockedUntil();
        if (pausedUntil != null && now.isBefore(pausedUntil)) {
            throw new ReauthenticationFailedException();   // no Argon2 work while paused
        }
        String hash = user.getPasswordHash();
        if (hash == null) {
            throw new ReauthenticationRequiredException();
        }
        String password = Passwords.normalise(rawPassword == null ? "" : rawPassword);
        // Argon2 (64 MB): the same small pool as login and signup
        boolean correct = passwordWork.call(() -> matches(password, hash));
        if (!correct) {
            transactions.executeWithoutResult(status -> {
                if (pausedUntil != null) {
                    users.resetReauthenticationFailures(userId);   // the last pause is over: count afresh
                }
                users.recordFailedReauthentication(userId, MAX_FAILURES, now.plus(PAUSE));
            });
            throw new ReauthenticationFailedException();
        }
        if (user.getReauthFailureCount() > 0 || pausedUntil != null) {
            transactions.executeWithoutResult(status -> users.resetReauthenticationFailures(userId));
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
