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
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "Authentication required",
            "Valid credentials are required to access this resource."),
    FORBIDDEN(HttpStatus.FORBIDDEN, "Access denied", "You do not have permission to perform this action."),
    NOT_FOUND(HttpStatus.NOT_FOUND, "Resource not found", "The requested resource does not exist."),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "Method not allowed",
            "This HTTP method is not supported for this resource."),
    NOT_ACCEPTABLE(HttpStatus.NOT_ACCEPTABLE, "Not acceptable", "The requested response format is not supported."),
    EMAIL_ALREADY_USED(HttpStatus.CONFLICT, "Email already registered", "An account with this email already exists."),
    CONFLICT(HttpStatus.CONFLICT, "Conflict", "The resource was changed by someone else. Reload and try again."),
    PAYLOAD_TOO_LARGE(HttpStatus.CONTENT_TOO_LARGE, "Request too large", "The request body is too large."),
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Unsupported media type",
            "Send the request body as application/json."),
    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "Too many requests", "Too many requests. Try again later."),
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
