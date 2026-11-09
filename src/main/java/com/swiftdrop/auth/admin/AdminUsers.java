package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.account.AccountDeletionService;
import com.swiftdrop.auth.audit.Actor;
import com.swiftdrop.auth.audit.AuditEntry;
import com.swiftdrop.auth.audit.AuditLog;
import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Identity step 9b: what the SwiftDrop admin portal does to a person, with the admin's own token. Every change is
 * audited in its own transaction. Two rules for block and delete: never your own account, never the last
 * administrator (so the service can always be administered).
 */
@Service
public class AdminUsers {

    private static final Logger log = LoggerFactory.getLogger(AdminUsers.class);
    private static final Pattern REASON = Pattern.compile("^[\\p{L}\\p{N} .,:;()_/#'-]{3,200}$");
    private static final List<String> REVIEWED_ROLES = List.of("ADMIN", "DISPATCHER", "MERCHANT");

    private final UserRepository users;
    private final RoleRepository roles;
    private final SessionService sessions;
    private final IdentityEvents identityEvents;
    private final AccountDeletionService deletion;
    private final AuditLog audit;
    private final JdbcTemplate jdbc;
    private final Clock clock;

    AdminUsers(UserRepository users, RoleRepository roles, SessionService sessions, IdentityEvents identityEvents,
               AccountDeletionService deletion, AuditLog audit, JdbcTemplate jdbc, Clock clock) {
        this.users = users;
        this.roles = roles;
        this.sessions = sessions;
        this.identityEvents = identityEvents;
        this.deletion = deletion;
        this.audit = audit;
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /** What the admin screen shows of one person: no password hash, no counters, no tokens. */
    public record UserDetail(UUID id, String email, boolean emailVerified, UserStatus status, List<String> roles,
                             Instant createdAt, Instant lastLoginAt, boolean googleLinked, int activeSessions) {
    }

    /** One line of the access review: who holds a powerful role, and (since step 9) who granted it, when. */
    public record RoleHolder(UUID userId, String role, String grantedBy, Instant grantedAt) {
    }

    @Transactional(readOnly = true)
    public UserDetail detail(UUID userId) {
        User user = users.findWithRolesById(userId).filter(found -> found.getStatus() != UserStatus.DELETED)
                .orElseThrow(() -> new AdminUsersException(ErrorCode.USER_NOT_FOUND));
        Boolean google = jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM identity.oauth_accounts WHERE user_id = ?)", Boolean.class, userId);
        Integer active = jdbc.queryForObject("SELECT count(DISTINCT family_id) FROM identity.refresh_tokens"
                        + " WHERE user_id = ? AND revoked_at IS NULL AND used_at IS NULL AND expires_at > ?",
                Integer.class, userId, Timestamp.from(clock.instant()));
        return new UserDetail(user.getId(), user.getEmail(), user.isEmailVerified(), user.getStatus(),
                user.roleNames(), user.getCreatedAt(), user.getLastLoginAt(), Boolean.TRUE.equals(google),
                active == null ? 0 : active);
    }

    /** Status DISABLED, every session ends, receivers get account-disabled. Blocking a blocked person is a no-op. */
    @Transactional
    public UserDetail block(Actor actor, UUID userId, String reason) {
        String why = checkReason(reason);
        User user = lockOther(actor, userId);
        if (user.getStatus() != UserStatus.DISABLED) {
            if (isActiveAdmin(user)) {
                requireAnotherActiveAdmin();
            }
            user.disable();
            users.saveAndFlush(user);
            sessions.endAllSessions(userId, RevokeReason.ACCOUNT_DISABLED);
            identityEvents.disabled(userId);
            audit.record(AuditEntry.onUser(actor, "user.blocked", userId, Map.of("reason", why)));
            log.warn("User blocked user={} by={}", userId, actor.id());
        }
        return detail(userId);
    }

    @Transactional
    public UserDetail unblock(Actor actor, UUID userId, String reason) {
        String why = checkReason(reason);
        User user = lockOther(actor, userId);
        if (user.getStatus() == UserStatus.DISABLED) {
            user.enable();
            users.saveAndFlush(user);
            identityEvents.enabled(userId);
            audit.record(AuditEntry.onUser(actor, "user.unblocked", userId, Map.of("reason", why)));
            log.info("User unblocked user={} by={}", userId, actor.id());
        }
        return detail(userId);
    }

    /** The same erasure as "delete my account" (tombstone now, hard delete after the receivers confirm). */
    @Transactional
    public void delete(Actor actor, UUID userId, String reason) {
        String why = checkReason(reason);
        User user = lockOther(actor, userId);
        if (isActiveAdmin(user)) {
            requireAnotherActiveAdmin();
        }
        deletion.tombstone(user, actor, Map.of("by", actor.type() == Actor.Type.BREAK_GLASS ? "break-glass" : "admin",
                "reason", why));
    }

    /** Logs the person out everywhere (e.g. a stolen phone). Access tokens already out end within 15 minutes. */
    @Transactional
    public UserDetail endSessions(Actor actor, UUID userId, String reason) {
        String why = checkReason(reason);
        lockOther(actor, userId);
        sessions.endAllSessions(userId, RevokeReason.ENDED_BY_ADMIN);
        audit.record(AuditEntry.onUser(actor, "sessions.ended", userId, Map.of("reason", why)));
        return detail(userId);
    }

    @Transactional(readOnly = true)
    public List<RoleHolder> accessReview() {
        // The newest audited grant of that role to that person (null: granted before the audit log existed)
        return jdbc.query("""
                SELECT u.id, r.name AS role, g.actor_id, g.at
                FROM identity.users u
                JOIN identity.user_roles ur ON ur.user_id = u.id
                JOIN identity.roles r ON r.id = ur.role_id
                LEFT JOIN LATERAL (
                    SELECT a.actor_id, a.at FROM identity.audit_log a
                    WHERE a.target_id = u.id::text
                      AND (a.action = 'role.granted' AND a.details::jsonb ->> 'role' = r.name
                        OR a.action = 'role-application.decided' AND a.details::jsonb ->> 'role' = r.name
                           AND a.details::jsonb ->> 'decision' = 'APPROVE'
                        OR r.name = 'MERCHANT' AND (a.action = 'merchant.decided'
                           AND a.details::jsonb ->> 'decision' = 'APPROVE' OR a.action = 'merchant.status-changed'
                           AND a.details::jsonb ->> 'change' = 'REINSTATE'))
                    ORDER BY a.seq DESC LIMIT 1) g ON true
                WHERE r.name = ANY (?::varchar[]) AND u.status <> 'DELETED'
                ORDER BY r.name, u.id""",
                (rs, row) -> new RoleHolder(rs.getObject("id", UUID.class), rs.getString("role"),
                        rs.getString("actor_id"), rs.getTimestamp("at") == null ? null
                        : rs.getTimestamp("at").toInstant()),
                "{" + String.join(",", REVIEWED_ROLES) + "}");
    }

    // Locks the person (same lock order as login, refresh and role changes); never the admin's own account
    private User lockOther(Actor actor, UUID userId) {
        if (actor.is(userId)) {
            throw new AdminUsersException(ErrorCode.CANNOT_ACT_ON_SELF);
        }
        users.lockById(userId);
        return users.findWithRolesById(userId).filter(user -> user.getStatus() != UserStatus.DELETED)
                .orElseThrow(() -> new AdminUsersException(ErrorCode.USER_NOT_FOUND));
    }

    // Only an ACTIVE admin can administer: removing an already blocked one never leaves the service without one
    private static boolean isActiveAdmin(User user) {
        return user.hasRole(RoleName.ADMIN) && user.getStatus() == UserStatus.ACTIVE;
    }

    // Lock first, then count (the same rule as revoking ADMIN): two parallel blocks can't remove the last two admins
    private void requireAnotherActiveAdmin() {
        roles.lockByName(RoleName.ADMIN);
        Integer activeAdmins = jdbc.queryForObject("SELECT count(*) FROM identity.users u JOIN identity.user_roles ur"
                + " ON ur.user_id = u.id JOIN identity.roles r ON r.id = ur.role_id"
                + " WHERE r.name = 'ADMIN' AND u.status = 'ACTIVE'", Integer.class);
        if (activeAdmins == null || activeAdmins <= 1) {
            throw new AdminUsersException(ErrorCode.LAST_ADMIN);
        }
    }

    /**
     * A short reason is required. It is kept for a year in a log that can't be edited, so only plain words, numbers
     * and simple punctuation: no email addresses (no "@"), no "+" phone numbers, no line breaks. Write a ticket id,
     * not the person's details.
     */
    public static String checkReason(String reason) {
        String trimmed = reason == null ? "" : reason.strip();
        if (!REASON.matcher(trimmed).matches()) {
            throw new AdminUsersException(ErrorCode.VALIDATION_FAILED);
        }
        return trimmed;
    }

    static final class AdminUsersException extends DomainException {
        AdminUsersException(ErrorCode code) {
            super(code);
        }
    }
}
