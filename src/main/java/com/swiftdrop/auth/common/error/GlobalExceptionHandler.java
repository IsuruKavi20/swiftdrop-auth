package com.swiftdrop.auth.common.error;

import com.swiftdrop.auth.common.web.PayloadTooLargeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;

/**
 * The single place where exceptions become HTTP responses. Every response body is
 * RFC 9457 Problem Details with a fixed, safe text; details of unexpected errors go to the log only.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final String RETRY_AFTER_SECONDS = "1";
    private static final String BRACKET_CONTENT = "\\[[^\\]]*\\]";

    @ExceptionHandler(DomainException.class)
    ResponseEntity<ProblemDetail> handleDomain(DomainException ex) {
        ProblemDetail body = ProblemDetails.of(ex.errorCode());
        if (!ex.violations().isEmpty()) {
            body.setProperty("errors", ex.violations());
        }
        ResponseEntity.BodyBuilder response = ResponseEntity.status(ex.errorCode().status());
        // Overload / rate limits tell well-behaved clients when to come back (RFC 9110 Retry-After)
        if (ex.errorCode().status().value() == 503 || ex.errorCode().status().value() == 429) {
            response.header(HttpHeaders.RETRY_AFTER, RETRY_AFTER_SECONDS);
        }
        return response.body(body);
    }

    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    ResponseEntity<ProblemDetail> handleStaleUpdate(ObjectOptimisticLockingFailureException ex) {
        return respond(ErrorCode.CONFLICT);
    }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException ex) {
        return unauthenticated();
    }

    // A method-level check (e.g. @PreAuthorize) failing for someone NOT logged in is a 401, not a 403
    @ExceptionHandler(AccessDeniedException.class)
    ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex) {
        Authentication current = SecurityContextHolder.getContext().getAuthentication();
        if (current == null || current instanceof AnonymousAuthenticationToken) {
            return unauthenticated();
        }
        return respond(ErrorCode.FORBIDDEN);
    }

    // Exception messages can contain personal data (e.g. "Key (email)=(...)" from the database),
    // so ERROR logs carry only the exception types; the full detail is available at DEBUG.
    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> handleUnexpected(Exception ex) {
        Throwable rootCause = NestedExceptionUtils.getMostSpecificCause(ex);
        log.error("Unhandled exception type={} rootCause={}", ex.getClass().getName(), rootCause.getClass().getName());
        log.debug("Unhandled exception detail", ex);
        return respond(ErrorCode.INTERNAL_ERROR);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ProblemDetail body = ProblemDetails.of(ErrorCode.VALIDATION_FAILED);
        List<FieldViolation> violations = ex.getBindingResult().getFieldErrors().stream()
                // Map keys / indexes inside [...] come from the client, so they are never echoed
                .map(error -> new FieldViolation(error.getField().replaceAll(BRACKET_CONTENT, "[]"), error.getCode()))
                .toList();
        body.setProperty("errors", violations);
        return handleExceptionInternal(ex, body, headers, status, request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        // The size-limit filter aborts oversized bodies while the JSON parser is reading them
        if (NestedExceptionUtils.getMostSpecificCause(ex) instanceof PayloadTooLargeException tooLarge) {
            return handleExceptionInternal(ex, ProblemDetails.of(tooLarge.errorCode()), headers,
                    tooLarge.errorCode().status(), request);
        }
        return handleExceptionInternal(ex, ProblemDetails.of(ErrorCode.MALFORMED_REQUEST), headers, status, request);
    }

    /** Spring's built-in MVC errors (404, 405, 415, ...) get our safe body instead of Spring's default text. */
    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {
        Object safeBody = isOurs(body) ? body : ProblemDetails.of(ErrorCode.forStatus(status.value()));
        return super.handleExceptionInternal(ex, safeBody, headers, status, request);
    }

    private static boolean isOurs(Object body) {
        return body instanceof ProblemDetail problem
                && problem.getProperties() != null
                && problem.getProperties().containsKey("code");
    }


    private static ResponseEntity<ProblemDetail> unauthenticated() {
        return ResponseEntity.status(ErrorCode.UNAUTHENTICATED.status())
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .body(ProblemDetails.of(ErrorCode.UNAUTHENTICATED));
    }

    private static ResponseEntity<ProblemDetail> respond(ErrorCode code) {
        return ResponseEntity.status(code.status()).body(ProblemDetails.of(code));
    }
}
