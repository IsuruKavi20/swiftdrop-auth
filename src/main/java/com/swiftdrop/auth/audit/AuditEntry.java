package com.swiftdrop.auth.audit;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * One thing to record. {@code details} holds small facts (ids, counts, names of roles), never personal data:
 * values must be numbers, booleans or short strings without "@" (no email addresses slip in by mistake).
 */
public record AuditEntry(Actor actor, String action, String targetType, String targetId, Map<String, Object> details) {

    private static final Pattern ACTION = Pattern.compile("^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$");
    private static final int MAX_VALUE_LENGTH = 200;

    public AuditEntry {
        Objects.requireNonNull(actor, "actor");
        if (action == null || !ACTION.matcher(action).matches()) {
            throw new IllegalArgumentException("Action must look like 'role.granted': " + action);
        }
        details = details == null ? Map.of() : Map.copyOf(details);
        details.forEach(AuditEntry::checkValue);
    }

    /** Shortcut for the usual case: something done to a person. */
    public static AuditEntry onUser(Actor actor, String action, UUID userId, Map<String, Object> details) {
        return new AuditEntry(actor, action, "user", userId.toString(), details);
    }

    private static void checkValue(String key, Object value) {
        boolean allowed = value instanceof Number || value instanceof Boolean
                || value instanceof String text && text.length() <= MAX_VALUE_LENGTH && text.indexOf('@') < 0;
        if (!allowed) {
            throw new IllegalArgumentException("Audit detail '" + key + "' must be an id, number or flag");
        }
    }
}
