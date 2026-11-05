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
import java.util.Objects;
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

    // Identity profile (OIDC standard claims). Written only through setOwnProfile / applyProviderProfile.
    @Column(length = 300)
    private String name;

    @Column(name = "given_name", length = 300)
    private String givenName;

    @Column(name = "family_name", length = 300)
    private String familyName;

    @Column(name = "picture_url", length = 2048)
    private String pictureUrl;

    @Column(length = 35)
    private String locale;

    @Enumerated(EnumType.STRING)
    @Column(name = "profile_source", length = 10)
    private ProfileSource profileSource;

    @Column(name = "profile_updated_at")
    private Instant profileUpdatedAt;

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

    /** A new login email whose mailbox was just proven (email change confirmation link). */
    public void changeEmail(EmailAddress newEmail) {
        this.email = newEmail.value();
        this.emailVerified = true;
    }

    /**
     * The user's own profile (sign-up, later profile edits): from now on a provider can't overwrite it.
     *
     * @return true if anything changed
     */
    public boolean setOwnProfile(IdentityProfile profile, Instant now) {
        return replaceProfile(profile.name().map(PersonName::value).orElse(null),
                profile.givenName().map(PersonName::value).orElse(null),
                profile.familyName().map(PersonName::value).orElse(null),
                profile.pictureUrl().orElse(null), profile.locale().orElse(null), ProfileSource.USER, now);
    }

    /** Forget the profile entirely, e.g. a name typed by someone who never proved they own this mailbox. */
    public void clearProfile(Instant now) {
        replaceProfile(null, null, null, null, null, null, now);
    }

    /**
     * Profile from Google login. A Google-owned profile follows Google's latest values; a user-owned profile only
     * gets fields the user never set. Missing claims never erase what we have.
     *
     * @return true if anything changed
     */
    public boolean applyProviderProfile(IdentityProfile profile, Instant now) {
        if (profile.isEmpty()) {
            return false;
        }
        boolean usersOwn = profileSource == ProfileSource.USER;
        // Given/family name are parts of a name: never attach Google's parts to a name the user typed
        boolean nameIsUsers = usersOwn && name != null;
        String newGiven = nameIsUsers ? givenName
                : merge(givenName, profile.givenName().map(PersonName::value).orElse(null), usersOwn);
        String newFamily = nameIsUsers ? familyName
                : merge(familyName, profile.familyName().map(PersonName::value).orElse(null), usersOwn);
        return replaceProfile(merge(name, profile.name().map(PersonName::value).orElse(null), usersOwn),
                newGiven, newFamily, merge(pictureUrl, profile.pictureUrl().orElse(null), usersOwn),
                merge(locale, profile.locale().orElse(null), usersOwn),
                usersOwn ? ProfileSource.USER : ProfileSource.GOOGLE, now);
    }

    // The one place profile fields change: nothing differs -> nothing written, timestamp unchanged
    private boolean replaceProfile(String newName, String newGiven, String newFamily, String newPicture,
                                   String newLocale, ProfileSource newSource, Instant now) {
        boolean changed = !Objects.equals(newName, name) || !Objects.equals(newGiven, givenName)
                || !Objects.equals(newFamily, familyName) || !Objects.equals(newPicture, pictureUrl)
                || !Objects.equals(newLocale, locale) || newSource != profileSource;
        if (!changed) {
            return false;
        }
        this.name = newName;
        this.givenName = newGiven;
        this.familyName = newFamily;
        this.pictureUrl = newPicture;
        this.locale = newLocale;
        this.profileSource = newSource;
        this.profileUpdatedAt = now;
        return true;
    }

    // Absent incoming value: keep ours. User-owned: only fill a gap. Provider-owned: take the newer value.
    private static String merge(String current, String incoming, boolean usersOwn) {
        if (incoming == null || (usersOwn && current != null)) {
            return current;
        }
        return incoming;
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

    public String getName() {
        return name;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public String getLocale() {
        return locale;
    }

    public ProfileSource getProfileSource() {
        return profileSource;
    }

    public Instant getProfileUpdatedAt() {
        return profileUpdatedAt;
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
