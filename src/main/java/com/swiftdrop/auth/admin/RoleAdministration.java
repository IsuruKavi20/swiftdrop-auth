package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserStatus;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Admin role management and its rules. A grant reaches the user's token at the next refresh (≤ 15 min);
 * a revoke also ends all their sessions, so the lost role can't be refreshed back.
 */
@Service
public class RoleAdministration {

    private static final Logger log = LoggerFactory.getLogger(RoleAdministration.class);

    private final UserRepository users;
    private final RoleRepository roles;
    private final SessionService sessions;

    private final IdentityEvents identityEvents;

    public RoleAdministration(UserRepository users, RoleRepository roles, SessionService sessions, IdentityEvents identityEvents) {
        this.users = users;
        this.roles = roles;
        this.sessions = sessions;
        this.identityEvents = identityEvents;
    }

    @Transactional(readOnly = true)
    public UserView findByEmail(String rawEmail) {
        return users.findWithRolesByEmail(EmailAddress.of(rawEmail).value())
                .map(UserView::of)
                .orElseThrow(() -> new AdminException(ErrorCode.USER_NOT_FOUND));
    }

    /** Idempotent: granting a role the user already has changes nothing. */
    @Transactional
    public UserView grant(UUID actorId, UUID userId, RoleName role) {
        if (role == RoleName.MERCHANT) {
            // Merchants are approved through their own flow (Step 13), never by a bare role grant
            throw new AdminException(ErrorCode.ROLE_NOT_ASSIGNABLE);
        }
        User user = load(userId);
        if (!user.isEmailVerified() || user.getStatus() != UserStatus.ACTIVE) {
            // Same rule as AdminBootstrap: a role (above all ADMIN) only goes to a proven, active account
            throw new AdminException(ErrorCode.ACCOUNT_NOT_ELIGIBLE);
        }
        if (!user.hasRole(role)) {
            user.addRole(roles.findByName(role).orElseThrow());
            identityEvents.rolesChanged(user);
            log.info("Role granted: role={} user={} by={}", role, userId, actorId);
        }
        return UserView.of(user);
    }

    /** Idempotent: revoking a role the user does not have changes nothing. */
    @Transactional
    public UserView revoke(UUID actorId, UUID userId, RoleName role) {
        if (role == RoleName.MERCHANT) {
            // Merchants are suspended through merchant administration, which also stops their API clients
            throw new AdminException(ErrorCode.ROLE_NOT_ASSIGNABLE);
        }
        if (role == RoleName.ADMIN && actorId.equals(userId)) {
            // Prevents an admin from locking everyone (including themselves) out by accident
            throw new AdminException(ErrorCode.CANNOT_REMOVE_OWN_ADMIN);
        }
        User user = load(userId);
        if (!user.hasRole(role)) {
            return UserView.of(user);
        }
        if (user.getRoles().size() == 1) {
            throw new AdminException(ErrorCode.LAST_ROLE);
        }
        if (role == RoleName.ADMIN) {
            // Lock first, then count: concurrent revokes queue here, so the count is never stale
            roles.lockByName(RoleName.ADMIN);
            if (users.countWithRole(RoleName.ADMIN) <= 1) {
                throw new AdminException(ErrorCode.LAST_ADMIN);
            }
        }
        user.removeRole(role);
        identityEvents.rolesChanged(user);
        sessions.endAllSessions(userId, RevokeReason.ROLE_CHANGED);
        log.info("Role revoked: role={} user={} by={}", role, userId, actorId);
        return UserView.of(user);
    }

    // Locks the user row first (same lock order as login and refresh), then loads roles
    private User load(UUID userId) {
        users.lockById(userId);
        return users.findWithRolesById(userId).orElseThrow(() -> new AdminException(ErrorCode.USER_NOT_FOUND));
    }

    static final class AdminException extends DomainException {
        AdminException(ErrorCode code) {
            super(code);
        }
    }
}
