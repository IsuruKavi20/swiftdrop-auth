package com.swiftdrop.auth.merchant;

import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * "Become a merchant": a verified user applies, an admin decides. Approval gives the MERCHANT role, the only
 * way to get it (the admin role API refuses MERCHANT). Lock order everywhere: USER row first, then merchant row.
 */
@Service
public class MerchantApplications {

    static final Duration REAPPLY_AFTER = Duration.ofDays(7);
    private static final int LIST_LIMIT = 100;
    private static final Logger log = LoggerFactory.getLogger(MerchantApplications.class);

    private final MerchantRepository merchants;
    private final UserRepository users;
    private final RoleRepository roles;
    private final SessionService sessions;
    private final Clock clock;

    MerchantApplications(MerchantRepository merchants, UserRepository users, RoleRepository roles,
                         SessionService sessions, Clock clock) {
        this.merchants = merchants;
        this.users = users;
        this.roles = roles;
        this.sessions = sessions;
        this.clock = clock;
    }

    /** The business details we need to decide; nothing more (the merchant service keeps the shop profile). */
    public record Application(String businessName, String registrationNumber, String website) {
    }

    public enum Decision {
        APPROVE,
        REJECT
    }

    /** Later changes to an approved merchant, e.g. fraud found: SUSPEND, and REINSTATE when resolved. */
    public enum StatusChange {
        SUSPEND,
        REINSTATE
    }

    @Transactional
    public MerchantView apply(UUID userId, Application application) {
        Instant now = clock.instant();
        User user = users.lockById(userId).orElseThrow(() -> new MerchantException(ErrorCode.FORBIDDEN));
        if (!user.isEmailVerified() || !user.isUsable()) {
            throw new MerchantException(ErrorCode.ACCOUNT_NOT_ELIGIBLE);
        }
        Optional<Merchant> existing = merchants.lockByUserId(userId);
        if (existing.isEmpty()) {
            Merchant created = merchants.saveAndFlush(new Merchant(userId, application, now));
            log.info("Merchant application submitted: merchant={} user={}", created.getId(), userId);
            return MerchantView.of(created);
        }
        Merchant merchant = existing.get();
        if (merchant.getStatus() != MerchantStatus.REJECTED) {
            throw new MerchantException(ErrorCode.MERCHANT_APPLICATION_EXISTS);
        }
        if (now.isBefore(merchant.getDecidedAt().plus(REAPPLY_AFTER))) {
            throw new MerchantException(ErrorCode.MERCHANT_REAPPLY_TOO_SOON);
        }
        merchant.resubmit(application, now);
        log.info("Merchant application resubmitted: merchant={} user={}", merchant.getId(), userId);
        return MerchantView.of(merchant);
    }

    @Transactional(readOnly = true)
    public MerchantView findOwn(UUID userId) {
        return merchants.findByUserId(userId).map(MerchantView::of)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
    }

    @Transactional(readOnly = true)
    public List<MerchantView> list(MerchantStatus status) {
        return merchants.findByStatusOrderByCreatedAtAsc(status, Limit.of(LIST_LIMIT)).stream()
                .map(MerchantView::of).toList();
    }

    /** @param reason required for REJECT, must be null for APPROVE */
    @Transactional
    public MerchantView decide(UUID adminId, UUID merchantId, Decision decision, RejectionReason reason) {
        if ((decision == Decision.REJECT) != (reason != null)) {
            throw new MerchantException(ErrorCode.VALIDATION_FAILED);
        }
        UUID ownerId = merchants.findUserIdById(merchantId)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        if (ownerId.equals(adminId)) {
            // Separation of duties: whoever asks can't be whoever approves
            throw new MerchantException(ErrorCode.CANNOT_DECIDE_OWN_APPLICATION);
        }
        User owner = users.lockById(ownerId).orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        Merchant merchant = merchants.lockById(merchantId)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        if (merchant.getStatus() != MerchantStatus.PENDING) {
            throw new MerchantException(ErrorCode.MERCHANT_ALREADY_DECIDED);
        }
        Instant now = clock.instant();
        if (decision == Decision.APPROVE) {
            if (merchants.existsByRegistrationNumberAndStatusInAndIdNot(merchant.getRegistrationNumber(),
                    List.of(MerchantStatus.APPROVED, MerchantStatus.SUSPENDED), merchantId)) {
                throw new MerchantException(ErrorCode.MERCHANT_DUPLICATE_BUSINESS);
            }
            merchant.approve(adminId, now);
            if (!owner.hasRole(RoleName.MERCHANT)) {
                owner.addRole(roles.findByName(RoleName.MERCHANT).orElseThrow());
            }
            log.info("Merchant approved: merchant={} by={}", merchantId, adminId);
        } else {
            merchant.reject(adminId, reason, now);
            log.info("Merchant rejected: merchant={} reason={} by={}", merchantId, reason, adminId);
        }
        return MerchantView.of(merchant);
    }

    /**
     * SUSPEND: status SUSPENDED, MERCHANT role removed, all sessions ended; its API clients get no new tokens
     * (machine tokens already out die within 15 minutes). REINSTATE: back to APPROVED with the role.
     */
    @Transactional
    public MerchantView changeStatus(UUID adminId, UUID merchantId, StatusChange change) {
        UUID ownerId = merchants.findUserIdById(merchantId)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        if (ownerId.equals(adminId)) {
            throw new MerchantException(ErrorCode.CANNOT_DECIDE_OWN_APPLICATION);
        }
        User owner = users.lockById(ownerId).orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        Merchant merchant = merchants.lockById(merchantId)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        Instant now = clock.instant();
        if (change == StatusChange.SUSPEND && merchant.getStatus() == MerchantStatus.APPROVED) {
            merchant.suspend(adminId, now);
            owner.removeRole(RoleName.MERCHANT);
            sessions.endAllSessions(ownerId, RevokeReason.ROLE_CHANGED);
            log.warn("Merchant suspended: merchant={} by={}", merchantId, adminId);
        } else if (change == StatusChange.REINSTATE && merchant.getStatus() == MerchantStatus.SUSPENDED) {
            merchant.reinstate(adminId, now);
            if (!owner.hasRole(RoleName.MERCHANT)) {
                owner.addRole(roles.findByName(RoleName.MERCHANT).orElseThrow());
            }
            log.info("Merchant reinstated: merchant={} by={}", merchantId, adminId);
        } else {
            throw new MerchantException(ErrorCode.MERCHANT_INVALID_STATE);
        }
        return MerchantView.of(merchant);
    }
}
