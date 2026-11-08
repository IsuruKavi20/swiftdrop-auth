package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.user.RoleConflicts;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Limit;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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
    private final RoleRepository roles;
    private final IdentityEvents identityEvents;
    private final ApplicationEventPublisher events;
    private final ApplicationEmails emails;
    private final Clock clock;

    RoleApplications(RoleApplicationRepository applications, UserRepository users, RoleRepository roles,
                     IdentityEvents identityEvents, ApplicationEventPublisher events, ApplicationEmails emails,
                     Clock clock) {
        this.applications = applications;
        this.users = users;
        this.roles = roles;
        this.identityEvents = identityEvents;
        this.events = events;
        this.emails = emails;
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
        users.lockById(userId);
        RoleApplication application = applications.lockById(applicationId)
                .filter(found -> found.getUserId().equals(userId))
                .orElseThrow(() -> new RoleApplicationException(ErrorCode.ROLE_APPLICATION_NOT_FOUND));
        if (!application.isOpen()) {
            throw new RoleApplicationException(ErrorCode.ROLE_APPLICATION_CLOSED);
        }
        application.withdraw(clock.instant());
        log.info("Role application withdrawn: application={} user={}", applicationId, userId);
    }

    /**
     * The approvers' queue (identity step 7b). Only roles the caller may decide; asking for another role is refused.
     *
     * @param decidable roles the caller may decide (from their token's permissions)
     * @param role      optional filter
     */
    @Transactional(readOnly = true)
    public List<ApplicationForApprover> queue(Set<RoleName> decidable, RoleName role, ApplicationStatus status,
                                              int count) {
        if (decidable.isEmpty() || (role != null && !decidable.contains(role))) {
            throw new AccessDeniedException("Not allowed to decide these applications");
        }
        List<RoleApplication> found = applications.findByStatusAndRoleInOrderByCreatedAtAsc(status,
                role == null ? decidable : Set.of(role), Limit.of(count));
        Map<UUID, String> names = users.findAllById(found.stream().map(RoleApplication::getUserId).distinct().toList())
                .stream().filter(user -> user.getName() != null)
                .collect(Collectors.toMap(User::getId, User::getName));
        return found.stream().map(application -> ApplicationForApprover.of(application,
                names.get(application.getUserId()))).toList();
    }

    /**
     * Approve or reject (identity step 7b). Enforced HERE, on the server, never only in a screen: the caller may
     * decide this role; nobody decides their own application (four-eyes principle; the CVE-2026-15641 attack); the
     * application is still open. Approval re-checks the applicant NOW (active, verified, no conflicting role) and
     * gives the role and records the "roles changed" event in the same transaction.
     */
    @Transactional
    public RoleApplicationView decide(UUID approverId, Set<RoleName> tokenDecidable, UUID applicationId,
                                      Decision decision, String reason) {
        Set<RoleName> decidable = stillDecidable(approverId, tokenDecidable);
        UUID applicantId = applications.findUserIdById(applicationId)
                .orElseThrow(() -> new RoleApplicationException(ErrorCode.ROLE_APPLICATION_NOT_FOUND));
        if (applicantId.equals(approverId)) {
            throw new RoleApplicationException(ErrorCode.ROLE_SELF_DECISION);
        }
        // Lock order: the person first, then the application (the same order everywhere: no deadlock). The
        // application is read for the FIRST time under its lock, so its state is fresh: a decision that committed
        // while we waited is seen, never overwritten (no stale cached copy).
        User applicant = users.lockById(applicantId)
                .orElseThrow(() -> new RoleApplicationException(ErrorCode.ROLE_APPLICATION_NOT_FOUND));
        RoleApplication application = applications.lockById(applicationId)
                .orElseThrow(() -> new RoleApplicationException(ErrorCode.ROLE_APPLICATION_NOT_FOUND));
        if (!decidable.contains(application.getRole())) {
            throw new AccessDeniedException("Not allowed to decide this role");
        }
        if (!application.isOpen()) {
            throw new RoleApplicationException(ErrorCode.ROLE_APPLICATION_CLOSED);
        }
        Instant now = clock.instant();
        if (decision == Decision.APPROVE) {
            grant(applicant, application.getRole());
            application.decide(ApplicationStatus.APPROVED, approverId, clean(reason), now);
        } else {
            application.decide(ApplicationStatus.REJECTED, approverId, clean(reason), now);
        }
        // Outbox: stored in this transaction, emailed after commit (never for a decision that rolled back)
        events.publishEvent(new RoleApplicationDecided(applicationId));
        log.info("Role application decided: application={} role={} decision={} by={}", applicationId,
                application.getRole(), decision, approverId);
        return RoleApplicationView.of(application);
    }

    /** From the outbox listener: the decision email to the applicant (none for a deleted or disabled account). */
    @Transactional(readOnly = true)
    public void sendDecisionEmail(UUID applicationId) {
        applications.findById(applicationId).ifPresent(application -> users.findById(application.getUserId())
                .filter(User::isUsable)
                .ifPresent(applicant -> {
                    EmailAddress to = EmailAddress.of(applicant.getEmail());
                    if (application.getStatus() == ApplicationStatus.APPROVED) {
                        emails.sendApproved(to, application.getRole());
                    } else if (application.getStatus() == ApplicationStatus.REJECTED) {
                        emails.sendRejected(to, application.getRole(), application.getDecisionReason());
                    }
                }));
    }

    // The token may be up to 15 minutes old: an approver who lost the role (or the account) since then must not
    // decide. Only roles allowed BOTH by the token and by the approver's roles right now.
    private Set<RoleName> stillDecidable(UUID approverId, Set<RoleName> tokenDecidable) {
        User approver = users.findWithRolesById(approverId).filter(User::isUsable)
                .orElseThrow(() -> new AccessDeniedException("Approver not active"));
        Set<RoleName> nowDecidable = ApplicableRole.decidableWith(approver.permissionNames());
        Set<RoleName> decidable = tokenDecidable.stream().filter(nowDecidable::contains)
                .collect(Collectors.toUnmodifiableSet());
        if (decidable.isEmpty()) {
            throw new AccessDeniedException("Not allowed to decide role applications");
        }
        return decidable;
    }

    private void grant(User applicant, RoleName role) {
        if (!applicant.isUsable() || !applicant.isEmailVerified()) {
            throw new RoleApplicationException(ErrorCode.ACCOUNT_NOT_ELIGIBLE);
        }
        if (RoleConflicts.conflictFor(applicant, role).isPresent()) {
            throw new RoleApplicationException(ErrorCode.ROLE_CONFLICT);
        }
        if (!applicant.hasRole(role)) {
            applicant.addRole(roles.findByName(role).orElseThrow());
            identityEvents.rolesChanged(applicant);
        }
    }

    // Free text typed by a person (note, reason): trimmed, and control characters except line breaks removed
    // (the reason goes into a plain-text email)
    private static String clean(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        return text.strip().replaceAll("[\\p{Cc}&&[^\\n]]", "");
    }
}
