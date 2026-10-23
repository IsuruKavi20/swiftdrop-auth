package com.swiftdrop.auth.common.web;

/**
 * Every public route lives under a version prefix. A breaking change gets a new prefix (/api/v2)
 * while v1 keeps working; at that point Spring 7's built-in API versioning can replace this.
 */
public final class ApiPaths {

    public static final String V1 = "/api/v1";
    public static final String AUTH = V1 + "/auth";

    private ApiPaths() {
    }
}
