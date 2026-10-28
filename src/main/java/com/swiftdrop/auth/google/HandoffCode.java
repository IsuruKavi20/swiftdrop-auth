package com.swiftdrop.auth.google;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "login_handoff_codes")
public class HandoffCode {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "code_hash", nullable = false, updatable = false, length = 64)
    private String codeHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    // base64url(SHA-256(verifier)) from the browser that started the login
    @Column(name = "browser_challenge", nullable = false, updatable = false, length = 43)
    private String browserChallenge;

    protected HandoffCode() {
        // required by JPA
    }

    HandoffCode(UUID userId, String codeHash, String browserChallenge, Instant createdAt, Instant expiresAt) {
        this.userId = userId;
        this.browserChallenge = browserChallenge;
        this.codeHash = codeHash;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    UUID getId() {
        return id;
    }

    String getBrowserChallenge() {
        return browserChallenge;
    }

    UUID getUserId() {
        return userId;
    }
}
