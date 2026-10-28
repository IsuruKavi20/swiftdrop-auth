package com.swiftdrop.auth.google;

import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.InvalidEmailException;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Turns a verified Google identity into OUR user (deep dive 24, section 3). Google users are keyed by
 * {@code sub}, never by email; roles always come from our database, never from Google.
 */
@Service
public class GoogleAccountLinker {

    static final String PROVIDER = "google";
    private static final Logger log = LoggerFactory.getLogger(GoogleAccountLinker.class);

    private final OAuthAccountRepository accounts;
    private final UserRepository users;
    private final RoleRepository roles;
    private final SessionService sessions;
    private final Clock clock;

    GoogleAccountLinker(OAuthAccountRepository accounts, UserRepository users, RoleRepository roles,
                        SessionService sessions, Clock clock) {
        this.accounts = accounts;
        this.users = users;
        this.roles = roles;
        this.sessions = sessions;
        this.clock = clock;
    }

    /** Returns our user id, or throws {@link GoogleLoginRefusedException}. */
    @Transactional
    public UUID link(GoogleIdentity google) {
        if (google.sub() == null || google.sub().isBlank() || !google.emailVerified()) {
            throw new GoogleLoginRefusedException("Google email not verified");
        }
        Instant now = clock.instant();
        Optional<OAuthAccount> linked = accounts.findByProviderAndProviderUserId(PROVIDER, google.sub());
        if (linked.isPresent()) {
            return requireUsable(lock(linked.get().getUserId()), now).getId();
        }
        EmailAddress email = emailOf(google);
        // Only the id (not the entity), then lock: the locked row is read fresh, never from Hibernate's cache
        Optional<UUID> existingId = users.findIdByEmail(email.value());
        if (existingId.isEmpty()) {
            return createUser(email, google.sub(), now);
        }
        requireGoogleVouchesForTheMailbox(google, email);
        User user = requireUsable(lock(existingId.get()), now);
        if (accounts.existsByUserIdAndProvider(user.getId(), PROVIDER)) {
            throw new GoogleLoginRefusedException("Account already linked to another Google account");
        }
        if (!user.isEmailVerified()) {
            reclaim(user);
        }
        accounts.save(new OAuthAccount(user.getId(), PROVIDER, google.sub(), now));
        log.info("Google account linked: user={}", user.getId());
        return user.getId();
    }

    // Pre-hijack defence: whoever set the password never proved they own this mailbox; Google just did.
    // The owner keeps the account, the unproven password and every session made with it are destroyed.
    private void reclaim(User user) {
        user.removePassword();
        user.markEmailVerified();
        sessions.endAllSessions(user.getId(), RevokeReason.ACCOUNT_RECLAIMED);
        log.warn("Unverified password account reclaimed through Google: user={}", user.getId());
    }

    private UUID createUser(EmailAddress email, String sub, Instant now) {
        User user = new User(email, null);
        user.markEmailVerified();
        user.addRole(roles.findByName(RoleName.CUSTOMER).orElseThrow());
        UUID id = users.saveAndFlush(user).getId();
        accounts.save(new OAuthAccount(id, PROVIDER, sub, now));
        log.info("New account created through Google: user={}", id);
        return id;
    }

    // Linking an EXISTING account by email: for @gmail.com Google owns the mailbox; for other domains only a
    // Workspace account whose hd matches the email's domain proves the company still controls that address
    // (a recycled domain or a personal Google account registered with a work email must not take over)
    private static void requireGoogleVouchesForTheMailbox(GoogleIdentity google, EmailAddress email) {
        String domain = email.value().substring(email.value().lastIndexOf('@') + 1);
        boolean gmail = "gmail.com".equals(domain);
        boolean workspaceMatch = google.hostedDomain() != null && domain.equalsIgnoreCase(google.hostedDomain());
        if (!gmail && !workspaceMatch) {
            throw new GoogleLoginRefusedException("Google does not vouch for this domain");
        }
    }

    private User lock(UUID userId) {
        return users.lockById(userId).orElseThrow(() -> new GoogleLoginRefusedException("Linked user missing"));
    }

    private static User requireUsable(User user, Instant now) {
        if (!user.isActiveAt(now)) {
            throw new GoogleLoginRefusedException("Account not active");
        }
        return user;
    }

    private static EmailAddress emailOf(GoogleIdentity google) {
        try {
            return EmailAddress.of(google.email());
        } catch (InvalidEmailException unusable) {
            throw new GoogleLoginRefusedException("Google email unusable");
        }
    }
}
