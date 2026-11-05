package com.swiftdrop.auth.account;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** One request to change a user's login email (V12). Holds only hashes of the link tokens. */
@Entity
@Table(name = "email_change_requests")
class EmailChangeRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "old_email", nullable = false, updatable = false, length = 320)
    private String oldEmail;

    @Column(name = "new_email", nullable = false, updatable = false, length = 320)
    private String newEmail;

    @Column(name = "confirm_token_hash", length = 64)
    private String confirmTokenHash;

    @Column(name = "confirm_expires_at", nullable = false, updatable = false)
    private Instant confirmExpiresAt;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "revert_token_hash", length = 64)
    private String revertTokenHash;

    @Column(name = "revert_expires_at")
    private Instant revertExpiresAt;

    @Column(name = "reverted_at")
    private Instant revertedAt;

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected EmailChangeRequest() {
        // required by JPA
    }

    EmailChangeRequest(UUID userId, String oldEmail, String newEmail, Instant now, Instant confirmExpiresAt) {
        this.userId = userId;
        this.oldEmail = oldEmail;
        this.newEmail = newEmail;
        this.createdAt = now;
        this.confirmExpiresAt = confirmExpiresAt;
    }

    /** Still waiting for the new address to confirm. */
    boolean isOpenAt(Instant now) {
        return confirmedAt == null && cancelledAt == null && now.isBefore(confirmExpiresAt);
    }

    boolean hasConfirmToken() {
        return confirmTokenHash != null;
    }

    void issueConfirmToken(String tokenHash) {
        this.confirmTokenHash = tokenHash;
    }

    boolean hasRevertToken() {
        return revertTokenHash != null;
    }

    /** The old address's undo link, issued once the change is confirmed. */
    void issueRevertToken(String tokenHash, Instant expiresAt) {
        this.revertTokenHash = tokenHash;
        this.revertExpiresAt = expiresAt;
    }

    UUID getId() {
        return id;
    }

    UUID getUserId() {
        return userId;
    }

    String getOldEmail() {
        return oldEmail;
    }

    String getNewEmail() {
        return newEmail;
    }
}
