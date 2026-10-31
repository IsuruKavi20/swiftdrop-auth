package com.swiftdrop.auth.security;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Ownership rule: the caller may act on their OWN data, or on anyone's if they hold {@code permission}.
 * {@code owner} is a SpEL reference to the method argument holding the owner's user id, e.g.
 * {@code @RequireOwnerOrPermission(owner = "#courierId", permission = "delivery:read-all")}
 * (a courier sees only their deliveries; a dispatcher sees all of them).
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@PreAuthorize("{owner}?.toString() == authentication.name or hasAuthority('{permission}')")
public @interface RequireOwnerOrPermission {

    String owner();

    String permission();
}
