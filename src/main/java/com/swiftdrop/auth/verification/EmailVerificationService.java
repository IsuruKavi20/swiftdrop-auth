package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.common.web.FrontendProperties;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.InvalidEmailException;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionOperations;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/** Issues one-time verification links, verifies them, and handles resend requests. */
@Service
public class EmailVerificationService {

    private static final String VERIFY_PATH = "/verify-email";
    private static final String LOGIN_PATH = "/login";
    private static final Duration ONE_DAY = Duration.ofDays(1);
    private static final Logger log = LoggerFactory.getLogger(EmailVerificationService.class);

    private final UserRepository users;
    private final VerificationTokenRepository tokens;
    private final AccountEmailSender sender;
    private final ApplicationEventPublisher events;
    private final VerificationProperties settings;
    private final FrontendProperties frontend;
    private final Clock clock;
    private final TransactionOperations transactions;

    private final IdentityEvents identityEvents;

    public EmailVerificationService(UserRepository users, VerificationTokenRepository tokens, AccountEmailSender sender,
                                    ApplicationEventPublisher events, VerificationProperties settings,
                                    FrontendProperties frontend, Clock clock, TransactionOperations transactions, IdentityEvents identityEvents) {
        this.users = users;
        this.tokens = tokens;
        this.sender = sender;
        this.events = events;
        this.settings = settings;
        this.frontend = frontend;
        this.clock = clock;
        this.transactions = transactions;
        this.identityEvents = identityEvents;
    }

    /**
     * New token (older ones stop working) + email. Runs from the outbox listener, so failures are retried (a retry
     * simply issues a newer token). The token is committed BEFORE the mail leaves, so the link can never reach the
     * inbox before the server knows it.
     */
    public void issueVerification(UUID userId) {
        PendingMail mail = transactions.execute(status -> saveVerificationToken(userId));
        if (mail != null) {
            sender.sendVerification(mail.to(), mail.link());
        }
    }

    private PendingMail saveVerificationToken(UUID userId) {
        User user = users.findById(userId).orElse(null);
        if (user == null || user.isEmailVerified()) {
            return null;
        }
        Instant now = clock.instant();
        if (isFloodLimited(userId, now)) {
            // Silently skipped: the client got the same answer as always. The user ID is not personal data in logs.
            log.info("Verification email skipped (cooldown or daily limit) userId={}", userId);
            return null;
        }
        tokens.invalidateOpenTokens(userId, now);
        String token = VerificationTokens.newToken();
        tokens.save(new VerificationToken(userId, VerificationTokens.hash(token), now, now.plus(settings.tokenTtl())));
        // The token goes in the URL fragment (#): browsers never send it to servers or in Referer headers,
        // and email scanners that pre-fetch links can't use it. The frontend page POSTs it on the user's click.
        return new PendingMail(EmailAddress.of(user.getEmail()), frontend.link(VERIFY_PATH + "#token=" + token));
    }

    private record PendingMail(EmailAddress to, URI link) {
    }

    /** Someone signed up with an existing email: verified owner gets a heads-up, unverified gets a fresh link. */
    public void handleSignupAttemptOnExistingAccount(UUID userId) {
        User user = users.findById(userId).orElse(null);
        if (user == null) {
            return;
        }
        if (!user.isEmailVerified()) {
            issueVerification(userId);
            return;
        }
        sender.sendAlreadyRegistered(EmailAddress.of(user.getEmail()), frontend.link(LOGIN_PATH));
    }

    @Transactional
    public void verify(String token) {
        if (!VerificationTokens.isWellFormed(token)) {
            throw new InvalidVerificationTokenException();
        }
        Instant now = clock.instant();
        VerificationToken stored = tokens.findByTokenHash(VerificationTokens.hash(token))
                .orElseThrow(InvalidVerificationTokenException::new);
        // Check-and-use in one atomic UPDATE: if a concurrent request used it first, we get 0
        if (tokens.consumeIfUsable(stored.getId(), now) != 1) {
            throw new InvalidVerificationTokenException();
        }
        User verified = users.findById(stored.getUserId()).orElseThrow(InvalidVerificationTokenException::new);
        verified.markEmailVerified();
        // Only now does the person exist for SwiftDrop: a proven mailbox (same transaction as the change)
        identityEvents.registered(verified);
    }

    /** Never reveals whether the address has an account: callers always get the same answer. */
    @Transactional
    public void requestResend(String rawEmail) {
        EmailAddress email;
        try {
            email = EmailAddress.of(rawEmail);
        } catch (InvalidEmailException notAnEmail) {
            return;
        }
        users.findByEmail(email.value())
                .filter(user -> !user.isEmailVerified())
                .ifPresent(user -> events.publishEvent(new VerificationEmailRequested(user.getId())));
    }

    // Stops anyone from flooding a victim's inbox through resend or repeated signups (and absorbs
    // duplicate deliveries from the outbox's at-least-once retries)
    private boolean isFloodLimited(UUID userId, Instant now) {
        return tokens.existsByUserIdAndCreatedAtAfter(userId, now.minus(settings.resendCooldown()))
                || tokens.countByUserIdAndCreatedAtAfter(userId, now.minus(ONE_DAY)) >= settings.maxEmailsPerDay();
    }
}
