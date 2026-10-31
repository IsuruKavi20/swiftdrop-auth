package com.swiftdrop.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 320)
    private String email;

    @Column(name = "password_hash")
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified;

    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "last_failed_login_at")
    private Instant lastFailedLoginAt;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    // Timestamps come from the application clock (all writes go through JPA). The DB defaults
    // are only a safety net for raw SQL inserts; raw SQL updates do not refresh updated_at.
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    // Optimistic locking: UPDATE ... WHERE version = ?; a stale copy fails instead of overwriting
    @Version
    @Column(nullable = false)
    private long version;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    protected User() {
        // required by JPA
    }

    public User(EmailAddress email, String passwordHash) {
        this.email = email.value();
        this.passwordHash = passwordHash;
    }

    public void addRole(Role role) {
        roles.add(role);
    }

    public void removeRole(RoleName name) {
        roles.removeIf(role -> role.getName() == name);
    }

    public boolean hasRole(RoleName name) {
        return roles.stream().anyMatch(role -> role.getName() == name);
    }

    /**
     * Account status allows use (not DISABLED/LOCKED by an admin). The temporary failed-password lock is NOT part
     * of this: it only blocks password logins, so a stranger's typos can't block Google login, refresh or merchant APIs.
     */
    public boolean isUsable() {
        return status == UserStatus.ACTIVE;
    }

    /** Usable AND not in a temporary failed-password lock: the check for PASSWORD login only. */
    public boolean isActiveAt(Instant now) {
        boolean temporarilyLocked = lockedUntil != null && now.isBefore(lockedUntil);
        return status == UserStatus.ACTIVE && !temporarilyLocked;
    }

    /** Role names for the token's "roles" claim, sorted. */
    public List<String> roleNames() {
        return roles.stream().map(role -> role.getName().name()).sorted().toList();
    }

    /** Union of the roles' permissions for the token's "entitlements" claim, sorted. */
    public List<String> permissionNames() {
        return roles.stream().flatMap(role -> role.permissionNames().stream()).distinct().sorted().toList();
    }

    /** Removes the password: the account can then only log in with Google (until a password reset sets one). */
    public void removePassword() {
        this.passwordHash = null;
    }

    public void markEmailVerified() {
        this.emailVerified = true;
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public UserStatus getStatus() {
        return status;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public int getFailedLoginCount() {
        return failedLoginCount;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public long getVersion() {
        return version;
    }

    public Set<Role> getRoles() {
        return Collections.unmodifiableSet(roles);
    }
}
