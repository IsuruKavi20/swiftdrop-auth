package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.login.Reauthentication;
import com.swiftdrop.auth.login.ReauthenticationFailedException;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.session.SessionTokens;
import com.swiftdrop.auth.signup.PasswordPolicy;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.UUID;

/**
 * Changing my password (identity step 3c). Every old session ends, including this device's: the device gets
 * brand-new tokens in the response, so even a copied refresh token of this device stops working.
 */
@Service
public class PasswordChangeService {

    private static final Logger log = LoggerFactory.getLogger(PasswordChangeService.class);

    private final Reauthentication reauthentication;
    private final PasswordPolicy policy;
    private final PasswordEncoder encoder;
    private final Bulkhead passwordWork;
    private final UserRepository users;
    private final SessionService sessions;
    private final ApplicationEventPublisher events;
    private final TransactionTemplate transactions;
    private final SecurityEmails emails;
    private final Clock clock;

    private final IdentityEvents identityEvents;

    PasswordChangeService(Reauthentication reauthentication, PasswordPolicy policy, PasswordEncoder encoder,
                          Bulkhead passwordWork, UserRepository users, SessionService sessions,
                          ApplicationEventPublisher events, TransactionTemplate transactions, SecurityEmails emails,
                          Clock clock, IdentityEvents identityEvents) {
        this.reauthentication = reauthentication;
        this.policy = policy;
        this.encoder = encoder;
        this.passwordWork = passwordWork;
        this.users = users;
        this.sessions = sessions;
        this.events = events;
        this.transactions = transactions;
        this.emails = emails;
        this.clock = clock;
        this.identityEvents = identityEvents;
    }

    /** Slow work (Argon2 twice, the breach check) runs before the short database transaction. */
    public SessionTokens change(UUID userId, String currentPassword, String rawNewPassword) {
        reauthentication.requireCurrentPassword(userId, currentPassword);
        User user = users.findById(userId).orElseThrow(ReauthenticationFailedException::new);
        String verifiedHash = user.getPasswordHash();
        // The same rules as sign-up: NIST length, not the email or service name, not in a known breach
        String newHash = passwordWork.call(() ->
                encoder.encode(policy.validate(rawNewPassword, EmailAddress.of(user.getEmail()))));
        return transactions.execute(status -> {
            // User row first (the same lock order as refresh and role changes), then check what we verified
            User locked = users.lockById(userId).filter(User::isUsable)
                    .orElseThrow(ReauthenticationFailedException::new);
            if (!verifiedHash.equals(locked.getPasswordHash())
                    || users.replacePasswordHash(userId, verifiedHash, newHash, clock.instant()) != 1) {
                throw new PasswordChangedMeanwhileException();   // someone changed it meanwhile: start again
            }
            identityEvents.passwordChanged(userId);
            sessions.endAllSessions(userId, RevokeReason.PASSWORD_CHANGED);
            events.publishEvent(new PasswordChanged(userId));
            log.info("Password changed, all sessions ended user={}", userId);
            return sessions.start(locked);
        });
    }

    /** From the outbox listener: the notice to the owner. */
    @Transactional(readOnly = true)
    public void sendPasswordChangedEmail(UUID userId) {
        // Never to a tombstone (an account deleted before this email went out)
        users.findById(userId).filter(User::isUsable)
                .ifPresent(user -> emails.sendPasswordChanged(EmailAddress.of(user.getEmail())));
    }
}
