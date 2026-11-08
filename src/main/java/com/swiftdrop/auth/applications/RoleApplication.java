package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.user.RoleName;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** One application for a role (V20). Open while PENDING; a decision or withdrawal closes it for good. */
@Entity
@Table(name = "role_applications")
class RoleApplication {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false, length = 20)
    private RoleName role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private ApplicationStatus status = ApplicationStatus.PENDING;

    @Column(length = 500, updatable = false)
    private String note;

    @Column(name = "decided_by")
    private UUID decidedBy;

    @Column(name = "decided_at")
    private Instant decidedAt;

    @Column(name = "decision_reason", length = 500)
    private String decisionReason;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected RoleApplication() {
        // required by JPA
    }

    RoleApplication(UUID userId, RoleName role, String note, Instant now) {
        this.userId = userId;
        this.role = role;
        this.note = note;
        this.createdAt = now;
    }

    boolean isOpen() {
        return status == ApplicationStatus.PENDING;
    }

    void withdraw(Instant now) {
        close(ApplicationStatus.WITHDRAWN, userId, null, now);
    }

    void decide(ApplicationStatus decision, UUID approver, String reason, Instant now) {
        close(decision, approver, reason, now);
    }

    private void close(ApplicationStatus newStatus, UUID by, String reason, Instant now) {
        this.status = newStatus;
        this.decidedBy = by;
        this.decisionReason = reason;
        this.decidedAt = now;
    }

    UUID getId() {
        return id;
    }

    UUID getUserId() {
        return userId;
    }

    RoleName getRole() {
        return role;
    }

    ApplicationStatus getStatus() {
        return status;
    }

    String getNote() {
        return note;
    }

    UUID getDecidedBy() {
        return decidedBy;
    }

    Instant getDecidedAt() {
        return decidedAt;
    }

    String getDecisionReason() {
        return decisionReason;
    }

    Instant getCreatedAt() {
        return createdAt;
    }
}
