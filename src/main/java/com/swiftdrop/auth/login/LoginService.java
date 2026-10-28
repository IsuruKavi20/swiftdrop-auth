package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.security.Passwords;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.session.SessionTokens;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.InvalidEmailException;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Email + password login. Built so a caller can't tell WHY a login failed (unknown email, wrong password,
 * locked, disabled all give the same answer) or learn it from timing (a full Argon2 check always runs).
 * Only after the correct password is "email not verified" revealed: the owner needs to know.
 */
@Service
public class LoginService {

    // A malformed email still does one lookup, so it costs the same time as a well-formed unknown one
    private static final String NO_SUCH_EMAIL = "no-such-account@invalid.invalid";

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final SessionService sessions;
    private final LoginRecorder recorder;
    private final Bulkhead passwordWork;
    private final Clock clock;
    // A real hash with current settings, checked when there is no account: same cost, result ignored
    private final String dummyHash;

    LoginService(UserRepository users, PasswordEncoder encoder, SessionService sessions, LoginRecorder recorder,
                 Bulkhead passwordWork, Clock clock) {
        this.users = users;
        this.encoder = encoder;
        this.sessions = sessions;
        this.recorder = recorder;
        this.passwordWork = passwordWork;
        this.clock = clock;
        this.dummyHash = encoder.encode(UUID.randomUUID().toString());
    }

    /** Returns an access token plus a refresh token that starts a new session. */
    public SessionTokens login(String rawEmail, String rawPassword) {
        Optional<User> account = findAccount(rawEmail);
        String password = Passwords.normalise(rawPassword == null ? "" : rawPassword);

        boolean correctPassword = passwordWork.call(() -> {
            String storedHash = account.map(User::getPasswordHash).orElse(null);
            boolean matches = safeMatches(password, storedHash != null ? storedHash : dummyHash);
            return matches && storedHash != null;
        });

        Instant now = clock.instant();
        // Locked and disabled accounts are hidden behind the generic answer (OWASP)
        if (!correctPassword || !account.get().isActiveAt(now)) {
            throw new InvalidCredentialsException();
        }
        User user = account.get();
        if (!user.isEmailVerified()) {
            throw new EmailNotVerifiedException();
        }

        recorder.recordSuccessfulLogin(user.getId(), now, user.getPasswordHash(), upgradedHash(user, password));
        return sessions.start(user);
    }

    private Optional<User> findAccount(String rawEmail) {
        String lookup;
        try {
            lookup = EmailAddress.of(rawEmail).value();
        } catch (InvalidEmailException malformed) {
            lookup = NO_SUCH_EMAIL;
        }
        return users.findWithRolesByEmail(lookup);
    }

    // A stored hash with a missing/unknown {id} prefix must not turn into a 500: it simply doesn't match
    private boolean safeMatches(String password, String hash) {
        try {
            return encoder.matches(password, hash);
        } catch (IllegalArgumentException unreadableHash) {
            encoder.matches(password, dummyHash);   // keep the timing of a normal check
            return false;
        }
    }

    // While we have the plain password, re-hash it if the stored hash used older, weaker settings
    private String upgradedHash(User user, String password) {
        if (!encoder.upgradeEncoding(user.getPasswordHash())) {
            return null;
        }
        return passwordWork.call(() -> encoder.encode(password));
    }
}
