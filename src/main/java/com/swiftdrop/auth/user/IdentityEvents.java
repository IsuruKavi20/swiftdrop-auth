package com.swiftdrop.auth.user;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Records identity events (identity step 6a), always inside the caller's transaction: {@code MANDATORY} makes a call
 * outside one fail loudly instead of risking an event without its change (or a change without its event). Each event
 * gets the person's next version. Payloads hold only what a receiver needs: never passwords, hashes or tokens.
 */
@Component
public class IdentityEvents {

    private final JdbcTemplate jdbc;
    private final JsonMapper json;
    private final Clock clock;

    IdentityEvents(JdbcTemplate jdbc, JsonMapper json, Clock clock) {
        this.jdbc = jdbc;
        this.json = json;
        this.clock = clock;
    }

    /** A person whose email is proven: everything a receiver needs to create its copy. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void registered(User user) {
        Map<String, Object> data = profileOf(user);
        data.put("email", user.getEmail());
        data.put("email_verified", user.isEmailVerified());
        data.put("roles", user.roleNames());
        data.put("status", user.getStatus().name());
        record(user.getId(), IdentityEventType.REGISTERED, data);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void profileUpdated(User user) {
        record(user.getId(), IdentityEventType.PROFILE_UPDATED, profileOf(user));
    }

    /** The full new role list (simpler and safer for receivers than "added X, removed Y"). */
    @Transactional(propagation = Propagation.MANDATORY)
    public void rolesChanged(User user) {
        record(user.getId(), IdentityEventType.ROLES_CHANGED, new LinkedHashMap<>(Map.of("roles", user.roleNames())));
    }

    /** RISC identifier-changed: the new login email. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void identifierChanged(User user) {
        record(user.getId(), IdentityEventType.IDENTIFIER_CHANGED,
                new LinkedHashMap<>(Map.of("new-value", user.getEmail())));
    }

    /** CAEP credential-change (OpenID CAEP 1.0: credential_type, change_type). */
    @Transactional(propagation = Propagation.MANDATORY)
    public void passwordChanged(UUID userId) {
        record(userId, IdentityEventType.CREDENTIAL_CHANGE,
                new LinkedHashMap<>(Map.of("credential_type", "password", "change_type", "update")));
    }

    /** CAEP session-revoked: every session of the person ended, and why (a stable reason code, no details). */
    @Transactional(propagation = Propagation.MANDATORY)
    public void sessionsRevoked(UUID userId, String reason) {
        record(userId, IdentityEventType.SESSION_REVOKED, new LinkedHashMap<>(Map.of("reason", reason)));
    }

    /** RISC account-purged: the person is gone. No personal data at all, only the subject id. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void purged(UUID userId) {
        record(userId, IdentityEventType.ACCOUNT_PURGED, new LinkedHashMap<>());
    }

    private static Map<String, Object> profileOf(User user) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", user.getName());
        data.put("given_name", user.getGivenName());
        data.put("family_name", user.getFamilyName());
        data.put("picture", user.getPictureUrl());
        data.put("locale", user.getLocale());
        return data;
    }

    private void record(UUID userId, IdentityEventType type, Map<String, Object> data) {
        // The row lock this UPDATE takes also serialises two events of the same person: versions never collide
        Long version = jdbc.queryForObject("UPDATE identity.users SET identity_version = identity_version + 1"
                + " WHERE id = ? RETURNING identity_version", Long.class, userId);
        jdbc.update("INSERT INTO identity.identity_events (user_id, user_version, event_type, payload, occurred_at)"
                        + " VALUES (?, ?, ?, ?::jsonb, ?)", userId, version, type.uri(), json.writeValueAsString(data),
                Timestamp.from(clock.instant()));
    }
}
