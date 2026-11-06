package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.user.RoleConflicts;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Applying for a role (identity step 7a). Only COURIER and DISPATCHER (ADMIN never; MERCHANT has its own flow).
 * Rules: an active, verified account; not a role already held; no conflicting role (separation of duties); one open
 * application per role; 7 days after a rejection before applying again.
 */
@Service
public class RoleApplications {

    static final Duration REAPPLY_AFTER_REJECTION = Duration.ofDays(7);
    private static final Logger log = LoggerFactory.getLogger(RoleApplications.class);

    private final RoleApplicationRepository applications;
    private final UserRepository users;
    private final Clock clock;

    RoleApplications(RoleApplicationRepository applications, UserRepository users, Clock clock) {
        this.applications = applications;
        this.users = users;
        this.clock = clock;
    }

    /** @param role COURIER or DISPATCHER (the API only accepts those two) */
    @Transactional
    public RoleApplicationView apply(UUID userId, RoleName role, String note) {
        Instant now = clock.instant();
        // Locked: two applications at the same moment queue here (the unique index is the final guard)
        User user = users.lockById(userId).filter(User::isUsable).filter(User::isEmailVerified)
                .orElseThrow(() -> new BadCredentialsException("Account not active"));
        if (user.hasRole(role)) {
            throw new RoleApplicationException(ErrorCode.ROLE_ALREADY_HELD);
        }
        if (RoleConflicts.conflictFor(user, role).isPresent()) {
            throw new RoleApplicationException(ErrorCode.ROLE_CONFLICT);
        }
        if (applications.existsByUserIdAndRoleAndStatus(userId, role, ApplicationStatus.PENDING)) {
            throw new RoleApplicationException(ErrorCode.ROLE_APPLICATION_EXISTS);
        }
        if (applications.existsByUserIdAndRoleAndStatusAndDecidedAtAfter(userId, role, ApplicationStatus.REJECTED,
                now.minus(REAPPLY_AFTER_REJECTION))) {
            throw new RoleApplicationException(ErrorCode.ROLE_REAPPLY_TOO_SOON);
        }
        try {
            RoleApplication saved = applications.saveAndFlush(new RoleApplication(userId, role, clean(note), now));
            log.info("Role application opened: application={} role={} user={}", saved.getId(), role, userId);
            return RoleApplicationView.of(saved);
        } catch (DataIntegrityViolationException openAtTheSameMoment) {
            throw new RoleApplicationException(ErrorCode.ROLE_APPLICATION_EXISTS);
        }
    }

    @Transactional(readOnly = true)
    public List<RoleApplicationView> mine(UUID userId) {
        return applications.findByUserIdOrderByCreatedAtDesc(userId).stream().map(RoleApplicationView::of).toList();
    }

    /** Only the applicant's own open application; someone else's id answers "not found" (no probing). */
    @Transactional
    public void withdraw(UUID userId, UUID applicationId) {
        RoleApplication application = applications.findByIdAndUserId(applicationId, userId)
                .orElseThrow(() -> new RoleApplicationException(ErrorCode.ROLE_APPLICATION_NOT_FOUND));
        if (!application.isOpen()) {
            throw new RoleApplicationException(ErrorCode.ROLE_APPLICATION_CLOSED);
        }
        application.withdraw(clock.instant());
        log.info("Role application withdrawn: application={} user={}", applicationId, userId);
    }

    private static String clean(String note) {
        if (note == null || note.isBlank()) {
            return null;
        }
        return note.strip();
    }
}
