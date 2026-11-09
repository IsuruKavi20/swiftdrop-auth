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
}
