package com.swiftdrop.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/** 403 raised by security filters goes through the GlobalExceptionHandler too. */
@Component
public class ProblemDetailsAccessDeniedHandler implements AccessDeniedHandler {

    private final HandlerExceptionResolver resolver;

    public ProblemDetailsAccessDeniedHandler(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException exception) {
        // If writing the Problem Details body failed (e.g. odd Accept header), still send the right status
        if (resolver.resolveException(request, response, null, exception) == null && !response.isCommitted()) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
