package com.swiftdrop.auth.user;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * A JSON Merge Patch (RFC 7396) of the identity profile: a field that is present is changed, present with
 * {@code null} is removed, absent stays as it is. Only the editable profile fields are accepted.
 */
public final class ProfilePatch {

    public static final Set<String> FIELDS = Set.of("name", "given_name", "family_name", "picture", "locale");

    private final Map<String, String> changes;

    private ProfilePatch(Map<String, String> changes) {
        this.changes = Collections.unmodifiableMap(changes);
    }

    /** @param changes field name to new value ({@code null} = remove); unknown fields are rejected */
    public static ProfilePatch of(Map<String, String> changes) {
        for (String field : changes.keySet()) {
            if (!FIELDS.contains(field)) {
                throw new InvalidProfileException("body", "UnknownField");
            }
        }
        return new ProfilePatch(new HashMap<>(changes));
    }

    boolean touches(String field) {
        return changes.containsKey(field);
    }

    String valueOf(String field) {
        return changes.get(field);
    }

    /** Field names only: the values are personal data. */
    @Override
    public String toString() {
        return "ProfilePatch" + changes.keySet();
    }
}
