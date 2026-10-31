package com.swiftdrop.auth.merchant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

/** A merchant application and its decision. One row per user: re-applying resets the same row. */
@Entity
@Table(name = "merchants")
public class Merchant {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "business_name", nullable = false, length = 120)
    private String businessName;

    @Column(name = "registration_number", nullable = false, length = 50)
    private String registrationNumber;

    @Column(length = 255)
    private String website;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private MerchantStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "decision_reason", length = 40)
    private RejectionReason decisionReason;

    @Column(name = "decided_by")
    private UUID decidedBy;

    @Column(name = "decided_at")
    private Instant decidedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(nullable = false)
    private long version;

    protected Merchant() {
        // required by JPA
    }

    Merchant(UUID userId, MerchantApplications.Application application, Instant now) {
        this.userId = userId;
        this.createdAt = now;
        resubmit(application, now);
    }

    /** A new (or repeated) application: back to PENDING with the new details, the old decision forgotten. */
    void resubmit(MerchantApplications.Application application, Instant now) {
        this.businessName = application.businessName();
        // "pv-12345 " and "PV-12345" are the same business
        this.registrationNumber = application.registrationNumber().strip().toUpperCase(Locale.ROOT);
        this.website = application.website();
        this.status = MerchantStatus.PENDING;
        this.decisionReason = null;
        this.decidedBy = null;
        this.decidedAt = null;
        this.updatedAt = now;
    }

    void approve(UUID adminId, Instant now) {
        decide(MerchantStatus.APPROVED, null, adminId, now);
    }

    void reject(UUID adminId, RejectionReason reason, Instant now) {
        decide(MerchantStatus.REJECTED, reason, adminId, now);
    }

    void suspend(UUID adminId, Instant now) {
        decide(MerchantStatus.SUSPENDED, null, adminId, now);
    }

    void reinstate(UUID adminId, Instant now) {
        decide(MerchantStatus.APPROVED, null, adminId, now);
    }

    private void decide(MerchantStatus decision, RejectionReason reason, UUID adminId, Instant now) {
        this.status = decision;
        this.decisionReason = reason;
        this.decidedBy = adminId;
        this.decidedAt = now;
        this.updatedAt = now;
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getBusinessName() {
        return businessName;
    }

    public String getRegistrationNumber() {
        return registrationNumber;
    }

    public String getWebsite() {
        return website;
    }

    public MerchantStatus getStatus() {
        return status;
    }

    public RejectionReason getDecisionReason() {
        return decisionReason;
    }

    public Instant getDecidedAt() {
        return decidedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
