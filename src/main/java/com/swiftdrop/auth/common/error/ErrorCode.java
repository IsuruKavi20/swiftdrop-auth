package com.swiftdrop.auth.common.error;

import org.springframework.http.HttpStatus;

import java.net.URI;
import java.util.Locale;

/**
 * Every error the API can return. Titles and details are fixed, safe texts:
 * they never contain user input, internal names or exception messages.
 */
public enum ErrorCode {

    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "Request validation failed", "One or more fields are invalid."),
    MALFORMED_REQUEST(HttpStatus.BAD_REQUEST, "Malformed request", "The request could not be read."),
    INVALID_EMAIL(HttpStatus.BAD_REQUEST, "Invalid email address", "The email address is not valid."),
    INVALID_OR_EXPIRED_TOKEN(HttpStatus.BAD_REQUEST, "Invalid or expired link",
            "This link is invalid or has expired. Request a new verification email."),
    WEAK_PASSWORD(HttpStatus.BAD_REQUEST, "Password not accepted",
            "The password does not meet the password rules. See errors for the reason."),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Login failed", "Invalid email or password."),
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Session ended", "Your session has ended. Log in again."),
    INVALID_LOGIN_CODE(HttpStatus.UNAUTHORIZED, "Sign-in expired", "This sign-in has expired. Please start again."),
    EMAIL_NOT_VERIFIED(HttpStatus.FORBIDDEN, "Email not verified",
            "Verify your email address before logging in. You can request a new verification link."),
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "Authentication required",
            "Valid credentials are required to access this resource."),
    FORBIDDEN(HttpStatus.FORBIDDEN, "Access denied", "You do not have permission to perform this action."),
    NOT_FOUND(HttpStatus.NOT_FOUND, "Resource not found", "The requested resource does not exist."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "User not found", "No user exists with this identifier."),
    ROLE_NOT_ASSIGNABLE(HttpStatus.BAD_REQUEST, "Role not assignable",
            "This role cannot be granted here. Merchant access is given through merchant approval."),
    CANNOT_REMOVE_OWN_ADMIN(HttpStatus.CONFLICT, "Cannot remove own admin role",
            "You cannot remove your own admin role. Ask another administrator."),
    LAST_ROLE(HttpStatus.CONFLICT, "Last role", "A user must keep at least one role."),
    MERCHANT_APPLICATION_EXISTS(HttpStatus.CONFLICT, "Application exists",
            "You already have a merchant application or merchant account."),
    MERCHANT_REAPPLY_TOO_SOON(HttpStatus.CONFLICT, "Too soon to re-apply",
            "Your last application was rejected recently. You can apply again 7 days after the decision."),
    MERCHANT_NOT_FOUND(HttpStatus.NOT_FOUND, "Merchant not found", "No such merchant application exists."),
    MERCHANT_ALREADY_DECIDED(HttpStatus.CONFLICT, "Already decided", "This application has already been decided."),
    CANNOT_DECIDE_OWN_APPLICATION(HttpStatus.FORBIDDEN, "Own application",
            "You cannot decide your own merchant application. Ask another administrator."),
    MERCHANT_NOT_APPROVED(HttpStatus.FORBIDDEN, "Merchant not approved",
            "API credentials are only available to approved merchants."),
    MERCHANT_CLIENT_LIMIT(HttpStatus.CONFLICT, "Client limit reached",
            "A merchant can have at most 2 active API clients. Revoke one first."),
    MERCHANT_CLIENT_NOT_FOUND(HttpStatus.NOT_FOUND, "Client not found", "No such API client exists."),
    MERCHANT_DUPLICATE_BUSINESS(HttpStatus.CONFLICT, "Business already registered",
            "A merchant with this business registration number already exists."),
    MERCHANT_INVALID_STATE(HttpStatus.CONFLICT, "Not possible now",
            "This action is not possible in the merchant's current state."),
    LAST_ADMIN(HttpStatus.CONFLICT, "Last administrator",
            "The last administrator cannot be removed. Make someone else an administrator first."),
    ACCOUNT_NOT_ELIGIBLE(HttpStatus.CONFLICT, "Account not eligible",
            "Roles can only be granted to active accounts with a verified email address."),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "Method not allowed",
            "This HTTP method is not supported for this resource."),
    NOT_ACCEPTABLE(HttpStatus.NOT_ACCEPTABLE, "Not acceptable", "The requested response format is not supported."),
    CONFLICT(HttpStatus.CONFLICT, "Conflict", "The resource was changed by someone else. Reload and try again."),
    PAYLOAD_TOO_LARGE(HttpStatus.CONTENT_TOO_LARGE, "Request too large", "The request body is too large."),
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Unsupported media type",
            "Send the request body as application/json."),
    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "Too many requests", "Too many requests. Try again later."),
    SERVICE_BUSY(HttpStatus.SERVICE_UNAVAILABLE, "Service busy",
            "Too many requests are being processed right now. Try again shortly."),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal error",
            "Something went wrong. Quote the requestId if you contact support.");

    private static final String TYPE_BASE = "https://swiftdrop.dev/problems/";

    private final HttpStatus status;
    private final String title;
    private final String detail;

    ErrorCode(HttpStatus status, String title, String detail) {
        this.status = status;
        this.title = title;
        this.detail = detail;
    }

    public HttpStatus status() {
        return status;
    }

    public String title() {
        return title;
    }

    public String detail() {
        return detail;
    }

    /** The code used for a status that Spring or the servlet container produced on its own. */
    public static ErrorCode forStatus(int status) {
        return switch (status) {
            case 401 -> UNAUTHENTICATED;
            case 403 -> FORBIDDEN;
            case 404 -> NOT_FOUND;
            case 405 -> METHOD_NOT_ALLOWED;
            case 406 -> NOT_ACCEPTABLE;
            case 409 -> CONFLICT;
            case 413 -> PAYLOAD_TOO_LARGE;
            case 415 -> UNSUPPORTED_MEDIA_TYPE;
            case 429 -> RATE_LIMITED;
            default -> status >= 400 && status < 500 ? MALFORMED_REQUEST : INTERNAL_ERROR;
        };
    }

    /** Stable, documentable identifier, e.g. https://swiftdrop.dev/problems/validation-failed */
    public URI type() {
        return URI.create(TYPE_BASE + name().toLowerCase(Locale.ROOT).replace('_', '-'));
    }
}
