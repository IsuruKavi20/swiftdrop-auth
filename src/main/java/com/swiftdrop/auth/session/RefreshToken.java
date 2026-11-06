package com.swiftdrop.auth.session;

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

/** One refresh token (only its hash). Revocation happens in bulk via {@link RefreshTokenRepository}. */
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "family_id", nullable = false, updatable = false)
    private UUID familyId;

    @Column(name = "token_hash", nullable = false, updatable = false, length = 64)
    private String tokenHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "family_expires_at", nullable = false, updatable = false)
    private Instant familyExpiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "revoke_reason", length = 30)
    private RevokeReason revokeReason;

    protected RefreshToken() {
        // required by JPA
    }

    RefreshToken(UUID userId, UUID familyId, String tokenHash, Instant createdAt, Instant expiresAt,
                 Instant familyExpiresAt) {
        this.userId = userId;
        this.familyId = familyId;
        this.tokenHash = tokenHash;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.familyExpiresAt = familyExpiresAt;
    }

    void markUsed(Instant now) {
        this.usedAt = now;
    }

    boolean isUsed() {
        return usedAt != null;
    }

    boolean isRevoked() {
        return revokedAt != null;
    }

    boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }

    UUID getUserId() {
        return userId;
    }

    Instant getCreatedAt() {
        return createdAt;
    }

    Instant getExpiresAt() {
        return expiresAt;
    }

    UUID getFamilyId() {
        return familyId;
    }

    Instant getFamilyExpiresAt() {
        return familyExpiresAt;
    }
}
