package com.swiftdrop.auth.account;

import com.swiftdrop.auth.audit.Actor;
import com.swiftdrop.auth.audit.AuditEntry;
import com.swiftdrop.auth.audit.AuditLog;
import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import com.swiftdrop.auth.common.web.FrontendRegistry;
import com.swiftdrop.auth.common.web.RequestFrontend;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.signup.PasswordPolicy;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.user.InvalidEmailException;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Forgot password (identity step 11a, OWASP Forgot Password Cheat Sheet): a one-time emailed link (30 minutes,
 * stored hashed) lets the owner choose a new password. Every session ends; nobody is logged in automatically.
 */
@Service
public class PasswordResetService {

    static final Duration LINK_LIFETIME = Duration.ofMinutes(30);
    private static final Duration COOLDOWN = Duration.ofSeconds(60);
    private static final Duration ONE_DAY = Duration.ofDays(1);
    private static final int MAX_LINKS_PER_DAY = 5;
    private static final String RESET_PATH = "/reset-password";
    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    private final UserRepository users;
    private final PasswordResetTokenRepository tokens;
    private final SecurityEmails emails;
    private final ApplicationEventPublisher events;
    private final FrontendRegistry frontends;
    private final RequestFrontend requestFrontend;
    private final PasswordPolicy policy;
    private final PasswordEncoder encoder;
    private final Bulkhead passwordWork;
    private final SessionService sessions;
    private final IdentityEvents identityEvents;
    private final AuditLog audit;
    private final TransactionTemplate transactions;
    private final Clock clock;

    PasswordResetService(UserRepository users, PasswordResetTokenRepository tokens, SecurityEmails emails,
                         ApplicationEventPublisher events, FrontendRegistry frontends, RequestFrontend requestFrontend,
                         PasswordPolicy policy, PasswordEncoder encoder, Bulkhead passwordWork,
                         SessionService sessions, IdentityEvents identityEvents, AuditLog audit,
                         TransactionTemplate transactions, Clock clock) {
        this.users = users;
        this.tokens = tokens;
        this.emails = emails;
        this.events = events;
        this.frontends = frontends;
        this.requestFrontend = requestFrontend;
        this.policy = policy;
        this.encoder = encoder;
        this.passwordWork = passwordWork;
        this.sessions = sessions;
        this.identityEvents = identityEvents;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** Never reveals whether the address has an account: callers always get the same answer. */
    @Transactional
    public void request(String rawEmail) {
        EmailAddress email;
        try {
            email = EmailAddress.of(rawEmail);
        } catch (InvalidEmailException notAnEmail) {
            return;
        }
        // Blocked or deleted accounts get nothing: a reset must not be a way around an admin's block
        users.findByEmail(email.value()).filter(User::isUsable)
                .ifPresent(user -> events.publishEvent(new PasswordResetRequested(user.getId(),
                        requestFrontend.currentId())));
    }

    /**
     * From the outbox listener: a new link (older ones stop working) + the email. The token is committed BEFORE the
     * mail leaves, so the link can never arrive before the server knows it.
     */
    public void issueLink(UUID userId, String frontendId) {
        PendingMail mail = transactions.execute(status -> saveToken(userId, frontendId));
        if (mail != null) {
            emails.sendPasswordReset(mail.to(), mail.link());
        }
    }

    private PendingMail saveToken(UUID userId, String frontendId) {
        User user = users.findById(userId).filter(User::isUsable).orElse(null);
        if (user == null) {
            return null;
        }
        Instant now = clock.instant();
        if (isFloodLimited(userId, now)) {
            log.info("Password reset email skipped (cooldown or daily limit) userId={}", userId);
            return null;
        }
        tokens.invalidateOpenTokens(userId, now);
        String token = OpaqueTokens.newToken();
        tokens.save(new PasswordResetToken(userId, OpaqueTokens.hash(token), now, now.plus(LINK_LIFETIME)));
        // In the #fragment: never sent to servers or in Referer headers, and useless to link-scanning mail filters
        return new PendingMail(EmailAddress.of(user.getEmail()),
                frontends.link(frontendId, RESET_PATH + "#token=" + token));
    }

    private record PendingMail(EmailAddress to, URI link) {
    }

    /**
     * Sets the new password. The slow work (breach check, Argon2) runs BEFORE the link is used, so a weak password
     * doesn't burn the link; the link is then used in one atomic UPDATE (two clicks can't both win).
     */
    public void confirm(String token, String rawNewPassword) {
        if (!OpaqueTokens.isWellFormed(token)) {
            throw new InvalidPasswordResetLinkException();
        }
        PasswordResetToken stored = tokens.findByTokenHash(OpaqueTokens.hash(token))
                .filter(found -> found.getConsumedAt() == null && found.getExpiresAt().isAfter(clock.instant()))
                .orElseThrow(InvalidPasswordResetLinkException::new);
        User user = users.findById(stored.getUserId()).filter(User::isUsable)
                .orElseThrow(InvalidPasswordResetLinkException::new);
        String newHash = passwordWork.call(() ->
                encoder.encode(policy.validate(rawNewPassword, EmailAddress.of(user.getEmail()))));
        transactions.executeWithoutResult(status -> apply(stored, newHash));
    }

    private void apply(PasswordResetToken stored, String newHash) {
        Instant now = clock.instant();
        UUID userId = stored.getUserId();
        // User row first (the same lock order as password change and refresh), then use the link
        User locked = users.lockById(userId).filter(User::isUsable)
                .orElseThrow(InvalidPasswordResetLinkException::new);
        if (tokens.consumeIfUsable(stored.getId(), now) != 1) {
            throw new InvalidPasswordResetLinkException();
        }
        locked.resetPassword(newHash, now);
        identityEvents.passwordChanged(userId);
        sessions.endAllSessions(userId, RevokeReason.PASSWORD_CHANGED);
        events.publishEvent(new PasswordChanged(userId));
        audit.record(AuditEntry.onUser(Actor.user(userId), "password.reset", userId, Map.of()));
        log.info("Password reset by email link, all sessions ended user={}", userId);
    }

    // Stops anyone from flooding a victim's inbox (and absorbs the outbox's at-least-once retries)
    private boolean isFloodLimited(UUID userId, Instant now) {
        return tokens.existsByUserIdAndCreatedAtAfter(userId, now.minus(COOLDOWN))
                || tokens.countByUserIdAndCreatedAtAfter(userId, now.minus(ONE_DAY)) >= MAX_LINKS_PER_DAY;
    }
}
