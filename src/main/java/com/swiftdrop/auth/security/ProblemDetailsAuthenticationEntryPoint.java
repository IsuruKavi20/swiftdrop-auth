package com.swiftdrop.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * 401 raised by security filters (before any controller) is handed to the same
 * GlobalExceptionHandler, so it gets the same Problem Details body as every other error.
 */
@Component
public class ProblemDetailsAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HandlerExceptionResolver resolver;

    public ProblemDetailsAuthenticationEntryPoint(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException exception) {
        // If writing the Problem Details body failed (e.g. odd Accept header), still send the right status
        if (resolver.resolveException(request, response, null, exception) == null && !response.isCommitted()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
