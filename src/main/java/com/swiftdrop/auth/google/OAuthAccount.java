package com.swiftdrop.auth.google;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** Link between an external login (Google {@code sub}) and our user. Never stores Google's tokens. */
@Entity
@Table(name = "oauth_accounts")
public class OAuthAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(nullable = false, updatable = false, length = 30)
    private String provider;

    @Column(name = "provider_user_id", nullable = false, updatable = false)
    private String providerUserId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected OAuthAccount() {
        // required by JPA
    }

    OAuthAccount(UUID userId, String provider, String providerUserId, Instant createdAt) {
        this.userId = userId;
        this.provider = provider;
        this.providerUserId = providerUserId;
        this.createdAt = createdAt;
    }

    String getProvider() {
        return provider;
    }

    String getProviderUserId() {
        return providerUserId;
    }

    Instant getCreatedAt() {
        return createdAt;
    }

    UUID getUserId() {
        return userId;
    }
}
