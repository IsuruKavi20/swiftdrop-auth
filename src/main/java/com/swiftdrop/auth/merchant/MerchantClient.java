package com.swiftdrop.auth.merchant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** One set of API credentials for a merchant's software. The secret itself is never stored, only its hash. */
@Entity
@Table(name = "merchant_clients")
public class MerchantClient {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "merchant_id", nullable = false, updatable = false)
    private UUID merchantId;

    @Column(name = "client_id", nullable = false, updatable = false, length = 25)
    private String clientId;

    @Column(name = "secret_hash", nullable = false, updatable = false, length = 64)
    private String secretHash;

    @Column(nullable = false, updatable = false, length = 60)
    private String name;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected MerchantClient() {
        // required by JPA
    }

    MerchantClient(UUID merchantId, String clientId, String secretHash, String name, Instant createdAt) {
        this.merchantId = merchantId;
        this.clientId = clientId;
        this.secretHash = secretHash;
        this.name = name;
        this.createdAt = createdAt;
    }

    // At most one write a minute: a busy integration must not turn every token request into an UPDATE
    void markUsed(Instant now) {
        if (lastUsedAt == null || lastUsedAt.isBefore(now.minusSeconds(60))) {
            this.lastUsedAt = now;
        }
    }

    void revoke(Instant now) {
        this.revokedAt = now;
    }

    boolean isActive() {
        return revokedAt == null;
    }

    UUID getMerchantId() {
        return merchantId;
    }

    public String getClientId() {
        return clientId;
    }

    String getSecretHash() {
        return secretHash;
    }

    public String getName() {
        return name;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }
}
