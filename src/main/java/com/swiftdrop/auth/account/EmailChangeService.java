package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.common.web.FrontendProperties;
import com.swiftdrop.auth.login.Reauthentication;
import com.swiftdrop.auth.login.ReauthenticationFailedException;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Changing the login email (identity step 3b). Nothing changes until the NEW address confirms; the OLD address
 * is told at once. The answer never reveals whether the new address already has an account.
 */
@Service
public class EmailChangeService {

    static final Duration CONFIRM_TTL = Duration.ofHours(1);
    private static final Duration COOLDOWN = Duration.ofSeconds(60);
    private static final int MAX_PER_DAY = 5;
    private static final String CONFIRM_PATH = "/confirm-email-change";
    // 72 hours (not 7 days): less time for someone who later gets the OLD mailbox to misuse the link
    static final Duration REVERT_TTL = Duration.ofHours(72);
    private static final String REVERT_PATH = "/revert-email-change";
    private static final Logger log = LoggerFactory.getLogger(EmailChangeService.class);

    private final Reauthentication reauthentication;
    private final SessionService sessions;
    private final UserRepository users;
    private final EmailChangeRequestRepository requests;
    private final ApplicationEventPublisher events;
    private final TransactionTemplate transactions;
    private final SecurityEmails emails;
    private final FrontendProperties frontend;
    private final Clock clock;

    private final IdentityEvents identityEvents;

    EmailChangeService(Reauthentication reauthentication, SessionService sessions, UserRepository users,
                       EmailChangeRequestRepository requests, ApplicationEventPublisher events,
                       TransactionTemplate transactions, SecurityEmails emails, FrontendProperties frontend,
                       Clock clock, IdentityEvents identityEvents) {
        this.reauthentication = reauthentication;
        this.sessions = sessions;
        this.users = users;
        this.requests = requests;
        this.events = events;
        this.transactions = transactions;
        this.emails = emails;
        this.frontend = frontend;
        this.clock = clock;
        this.identityEvents = identityEvents;
    }

    /** Re-authenticates (outside any transaction: Argon2 is slow), then records the request. */
    public void request(UUID userId, String rawNewEmail, String currentPassword) {
        EmailAddress newEmail = EmailAddress.of(rawNewEmail);
        reauthentication.requireCurrentPassword(userId, currentPassword);
        transactions.executeWithoutResult(status -> record(userId, newEmail));
    }

    private void record(UUID userId, EmailAddress newEmail) {
        Instant now = clock.instant();
        User user = users.lockById(userId).filter(User::isUsable).orElseThrow(ReauthenticationFailedException::new);
        if (user.getEmail().equals(newEmail.value())) {
            throw new EmailUnchangedException();
        }
        // Stops anyone from flooding a stranger's inbox with "confirm" mails; the answer stays the same
        if (requests.existsByUserIdAndCreatedAtAfter(userId, now.minus(COOLDOWN))
                || requests.countByUserIdAndCreatedAtAfter(userId, now.minus(Duration.ofDays(1))) >= MAX_PER_DAY) {
            log.info("Email change request skipped (cooldown or daily limit) user={}", userId);
            return;
        }
        requests.cancelOpen(userId, now);
        EmailChangeRequest request = requests.save(
                new EmailChangeRequest(userId, user.getEmail(), newEmail.value(), now, now.plus(CONFIRM_TTL)));
        // Outbox: stored in this transaction, sent after commit, retried on failure
        events.publishEvent(new EmailChangeRequested(request.getId()));
        log.info("Email change requested user={} request={}", userId, request.getId());
    }

    /**
     * From the outbox listener. The link's hash is committed BEFORE the mail leaves, so a link can never arrive
     * before the server knows it (a fast click or a mail scanner would otherwise get "invalid link"). Safe to run
     * twice: a request whose link was already issued is skipped. If sending fails, the hash is removed again so the
     * outbox retry issues a fresh link instead of skipping.
     */
    public void sendRequestEmails(UUID requestId) {
        IssuedLink link = transactions.execute(status -> issueConfirmLink(requestId));
        if (link == null) {
            return;
        }
        try {
            if (link.newAddressTaken()) {
                // Never a link to an address that has an account (and the requester can't tell the difference)
                emails.sendAddressAlreadyUsed(link.newEmail());
            } else {
                // Token in the URL fragment: browsers never send it to servers or in Referer headers
                emails.sendConfirmNewEmail(link.newEmail(), frontend.link(CONFIRM_PATH + "#token=" + link.token()));
            }
            emails.sendChangeRequested(link.oldEmail(), masked(link.newEmail()));
        } catch (RuntimeException sendFailed) {
            transactions.executeWithoutResult(status ->
                    requests.lockById(requestId).ifPresent(request -> request.issueConfirmToken(null)));
            throw sendFailed;
        }
    }

    private IssuedLink issueConfirmLink(UUID requestId) {
        EmailChangeRequest request = requests.lockById(requestId).orElse(null);
        if (request == null || !request.isOpenAt(clock.instant()) || request.hasConfirmToken()) {
            return null;
        }
        String token = OpaqueTokens.newToken();
        request.issueConfirmToken(OpaqueTokens.hash(token));
        EmailAddress newEmail = EmailAddress.of(request.getNewEmail());
        return new IssuedLink(token, EmailAddress.of(request.getOldEmail()), newEmail,
                users.existsByEmail(newEmail.value()));
    }

    /** A link whose hash is already committed; the raw token lives only in memory until it is mailed. */
    private record IssuedLink(String token, EmailAddress oldEmail, EmailAddress newEmail, boolean newAddressTaken) {
    }

    /**
     * The link from the NEW inbox: switches the login email (the mailbox is now proven). Sessions are kept: the
     * owner is usually the one doing this; the OLD address gets an undo link that also ends every session.
     */
    @Transactional
    public void confirm(String token) {
        if (!OpaqueTokens.isWellFormed(token)) {
            throw new InvalidEmailChangeLinkException();
        }
        Instant now = clock.instant();
        EmailChangeRequest request = requests.findByConfirmTokenHash(OpaqueTokens.hash(token))
                .orElseThrow(InvalidEmailChangeLinkException::new);
        User user = users.lockById(request.getUserId()).orElseThrow(InvalidEmailChangeLinkException::new);
        // The account must still have the address the request started from, and the new one must still be free
        if (!user.isUsable() || !user.getEmail().equals(request.getOldEmail())
                || users.existsByEmail(request.getNewEmail())) {
            throw new InvalidEmailChangeLinkException();
        }
        // Single use, also under concurrency: only one confirmation can turn the open request into confirmed
        if (requests.confirmIfOpen(request.getId(), now) != 1) {
            throw new InvalidEmailChangeLinkException();
        }
        user.changeEmail(EmailAddress.of(request.getNewEmail()));
        try {
            users.saveAndFlush(user);
            identityEvents.identifierChanged(user);
        } catch (DataIntegrityViolationException takenAtTheSameMoment) {
            // Another account took the address in the same instant: the unique email constraint decides
            throw new InvalidEmailChangeLinkException();
        }
        events.publishEvent(new EmailChangeConfirmed(request.getId()));
        log.info("Email changed user={} request={}", user.getId(), request.getId());
    }

    /**
     * The undo link from the OLD inbox: restores the old address and ends every session, so whoever made the
     * change is logged out. It wins even if the email was changed again since (an attacker staying one step
     * ahead), and it cancels any open change request.
     */
    @Transactional
    public void revert(String token) {
        if (!OpaqueTokens.isWellFormed(token)) {
            throw new InvalidEmailChangeLinkException();
        }
        Instant now = clock.instant();
        EmailChangeRequest request = requests.findByRevertTokenHash(OpaqueTokens.hash(token))
                .orElseThrow(InvalidEmailChangeLinkException::new);
        // A deleted or disabled account is never brought back by a link (it would restore erased data)
        User user = users.lockById(request.getUserId()).filter(User::isUsable)
                .orElseThrow(InvalidEmailChangeLinkException::new);
        if (requests.revertIfOpen(request.getId(), now) != 1) {
            throw new InvalidEmailChangeLinkException();
        }
        boolean takenByAnother = users.findIdByEmail(request.getOldEmail())
                .filter(owner -> !owner.equals(user.getId())).isPresent();
        if (takenByAnother) {
            throw new InvalidEmailChangeLinkException();
        }
        user.changeEmail(EmailAddress.of(request.getOldEmail()));
        try {
            users.saveAndFlush(user);
            identityEvents.identifierChanged(user);
        } catch (DataIntegrityViolationException takenAtTheSameMoment) {
            throw new InvalidEmailChangeLinkException();
        }
        // Last: cancelOpen clears the persistence context, so nothing below may use the entities read above
        requests.cancelOpen(user.getId(), now);
        sessions.endAllSessions(user.getId(), RevokeReason.EMAIL_CHANGE_UNDONE);
        log.warn("Email change undone by the old address, all sessions ended user={} request={}",
                user.getId(), request.getId());
    }

    /**
     * From the outbox listener: the undo link to the old address. The raw token never touches the outbox table.
     * Like the confirm link, its hash is committed before the mail leaves, and removed again if sending fails.
     */
    public void sendConfirmedEmails(UUID requestId) {
        IssuedLink link = transactions.execute(status -> issueRevertLink(requestId));
        if (link == null) {
            return;
        }
        try {
            emails.sendEmailChanged(link.oldEmail(), masked(link.newEmail()),
                    frontend.link(REVERT_PATH + "#token=" + link.token()));
        } catch (RuntimeException sendFailed) {
            transactions.executeWithoutResult(status ->
                    requests.lockById(requestId).ifPresent(request -> request.issueRevertToken(null, null)));
            throw sendFailed;
        }
    }

    private IssuedLink issueRevertLink(UUID requestId) {
        EmailChangeRequest request = requests.lockById(requestId).orElse(null);
        if (request == null || request.hasRevertToken()) {
            return null;
        }
        String token = OpaqueTokens.newToken();
        request.issueRevertToken(OpaqueTokens.hash(token), clock.instant().plus(REVERT_TTL));
        return new IssuedLink(token, EmailAddress.of(request.getOldEmail()),
                EmailAddress.of(request.getNewEmail()), false);
    }

    // "nimal.perera@example.com" -> "n***@example.com": the owner recognises it, a mailbox thief learns little
    static String masked(EmailAddress email) {
        String value = email.value();
        int at = value.indexOf('@');
        return value.charAt(0) + "***" + value.substring(at);
    }
}
