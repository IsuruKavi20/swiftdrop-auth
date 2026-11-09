package com.swiftdrop.auth.account;

import com.swiftdrop.auth.audit.Actor;
import com.swiftdrop.auth.audit.AuditEntry;
import com.swiftdrop.auth.audit.AuditLog;
import com.swiftdrop.auth.login.Reauthentication;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.login.ReauthenticationFailedException;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.user.AccountDeleted;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * "Delete my account" (identity step 3e; design doc section 7, step 1). After the password check, in one
 * transaction: tombstone the user, end every session, erase the email-change history, and announce AccountDeleted so
 * every module (and later SwiftDrop) removes its part.
 */
@Service
public class AccountDeletionService {

    private static final Logger log = LoggerFactory.getLogger(AccountDeletionService.class);

    private final Reauthentication reauthentication;
    private final UserRepository users;
    private final EmailChangeRequestRepository emailChanges;
    private final SessionService sessions;
    private final ApplicationEventPublisher events;
    private final TransactionTemplate transactions;
    private final Clock clock;

    private final IdentityEvents identityEvents;

    private final AuditLog audit;

    AccountDeletionService(Reauthentication reauthentication, UserRepository users,
                           EmailChangeRequestRepository emailChanges, SessionService sessions,
                           ApplicationEventPublisher events, TransactionTemplate transactions, Clock clock, IdentityEvents identityEvents, AuditLog audit) {
        this.reauthentication = reauthentication;
        this.users = users;
        this.emailChanges = emailChanges;
        this.sessions = sessions;
        this.events = events;
        this.transactions = transactions;
        this.clock = clock;
        this.identityEvents = identityEvents;
        this.audit = audit;
    }

    public void delete(UUID userId, String currentPassword) {
        reauthentication.requireCurrentPassword(userId, currentPassword);
        transactions.executeWithoutResult(status -> {
            User user = users.lockById(userId).orElseThrow(ReauthenticationFailedException::new);
            tombstone(user, Actor.user(userId), Map.of("by", "owner"));
        });
    }

    /**
     * The shared part of "delete my account" and an administrator's delete (identity step 9b), inside the caller's
     * transaction, on a user row the caller has LOCKED. Does nothing for an existing tombstone.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void tombstone(User user, Actor actor, Map<String, Object> details) {
        UUID userId = user.getId();
        if (user.getStatus() == UserStatus.DELETED) {
            return;   // two deletes at the same moment: the second finds the tombstone and does nothing
        }
        Instant now = clock.instant();
        user.beginDeletion(now);
        users.saveAndFlush(user);
        // Erases the old/new addresses and every link hash: an old undo link can't restore the address
        emailChanges.deleteByUserId(userId);
        sessions.endAllSessions(userId, RevokeReason.ACCOUNT_DELETED);
        identityEvents.purged(userId);
        events.publishEvent(new AccountDeleted(userId));
        audit.record(AuditEntry.onUser(actor, "account.deleted", userId, details));
        log.info("Account deleted (tombstone kept) user={} by={}", userId, actor.type());
    }
}
