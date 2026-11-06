package com.swiftdrop.auth.account;

import com.swiftdrop.auth.login.Reauthentication;
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
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
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

    AccountDeletionService(Reauthentication reauthentication, UserRepository users,
                           EmailChangeRequestRepository emailChanges, SessionService sessions,
                           ApplicationEventPublisher events, TransactionTemplate transactions, Clock clock) {
        this.reauthentication = reauthentication;
        this.users = users;
        this.emailChanges = emailChanges;
        this.sessions = sessions;
        this.events = events;
        this.transactions = transactions;
        this.clock = clock;
    }

    public void delete(UUID userId, String currentPassword) {
        reauthentication.requireCurrentPassword(userId, currentPassword);
        transactions.executeWithoutResult(status -> {
            Instant now = clock.instant();
            User user = users.lockById(userId).orElseThrow(ReauthenticationFailedException::new);
            if (user.getStatus() == UserStatus.DELETED) {
                return;   // two deletes at the same moment: the second finds the tombstone and does nothing
            }
            user.beginDeletion(now);
            users.saveAndFlush(user);
            // Erases the old/new addresses and every link hash: an old undo link can't restore the address
            emailChanges.deleteByUserId(userId);
            sessions.endAllSessions(userId, RevokeReason.ACCOUNT_DELETED);
            events.publishEvent(new AccountDeleted(userId));
            log.info("Account deleted (tombstone kept) user={}", userId);
        });
    }
}
