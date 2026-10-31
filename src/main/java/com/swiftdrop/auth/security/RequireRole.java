package com.swiftdrop.auth.security;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Caller must have this role, e.g. {@code @RequireRole("ADMIN")}. Prefer {@link RequirePermission}:
 * roles are coarse, permissions say exactly what is allowed.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@PreAuthorize("hasRole('{value}')")
public @interface RequireRole {

    String value();
}
