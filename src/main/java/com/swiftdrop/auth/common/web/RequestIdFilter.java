package com.swiftdrop.auth.common.web;

import com.swiftdrop.auth.common.error.ProblemDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Gives every request an ID: put in the logging MDC (so every log line carries it), returned in the
 * X-Request-Id response header and in error bodies. Runs before everything else, security included.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-Id";
    /** Kept on the request so later dispatches of the SAME request (e.g. to /error) reuse the same ID. */
    public static final String ATTRIBUTE = RequestIdFilter.class.getName() + ".requestId";

    // A client-sent ID is untrusted input that ends up in logs: only plain, short IDs are accepted,
    // anything else (e.g. containing line breaks to fake log entries) is replaced by our own.
    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9-]{8,64}$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestId = request.getAttribute(ATTRIBUTE) instanceof String existing
                ? existing
                : safeIdFrom(request.getHeader(HEADER));
        request.setAttribute(ATTRIBUTE, requestId);
        MDC.put(ProblemDetails.REQUEST_ID_KEY, requestId);
        response.setHeader(HEADER, requestId);
        try {
            chain.doFilter(request, response);
        } finally {
            // Threads are reused for later requests: never let this ID leak into them
            MDC.remove(ProblemDetails.REQUEST_ID_KEY);
        }
    }

    // Also run on error and async dispatches, so /error responses and logs carry the same ID
    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }

    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }

    private static String safeIdFrom(String candidate) {
        return candidate != null && SAFE_ID.matcher(candidate).matches()
                ? candidate
                : UUID.randomUUID().toString();
    }
}
