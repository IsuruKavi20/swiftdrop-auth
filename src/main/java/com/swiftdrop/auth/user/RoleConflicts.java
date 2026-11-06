package com.swiftdrop.auth.user;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Separation of duties (identity step 7, decided 2026-11-07): roles that must never be held by the same person.
 * A dispatcher decides who gets which delivery; a dispatcher who is also a courier could give themselves the best
 * jobs. Checked wherever a role is given: role applications AND the admin grant endpoint.
 */
public final class RoleConflicts {

    private static final Map<RoleName, Set<RoleName>> CONFLICTS = Map.of(
            RoleName.COURIER, Set.of(RoleName.DISPATCHER),
            RoleName.DISPATCHER, Set.of(RoleName.COURIER));

    private RoleConflicts() {
    }

    /** The role the user already holds that conflicts with {@code wanted}, if any. */
    public static Optional<RoleName> conflictFor(User user, RoleName wanted) {
        return CONFLICTS.getOrDefault(wanted, Set.of()).stream().filter(user::hasRole).findFirst();
    }
}
