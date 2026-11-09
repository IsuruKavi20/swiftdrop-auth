package com.swiftdrop.auth.audit;

import java.util.UUID;

/** Who did it: a person (by id), a service client, the service itself, or an operator using the break-glass tool. */
public record Actor(Type type, String id) {

    public enum Type { USER, SERVICE, SYSTEM, BREAK_GLASS }

    public static Actor user(UUID userId) {
        return new Actor(Type.USER, userId.toString());
    }

    public static Actor service(String clientId) {
        return new Actor(Type.SERVICE, clientId);
    }

    public static Actor system() {
        return new Actor(Type.SYSTEM, null);
    }

    /** An operator with cluster access, using deploy/oke/break-glass.ps1 (identity step 9e). */
    public static Actor breakGlass() {
        return new Actor(Type.BREAK_GLASS, "break-glass");
    }

    /** True when this actor is that person (nobody blocks, deletes or gives roles to themselves). */
    public boolean is(UUID userId) {
        return type == Type.USER && userId.toString().equals(id);
    }
}
