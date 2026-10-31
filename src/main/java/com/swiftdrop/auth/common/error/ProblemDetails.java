package com.swiftdrop.auth.common.error;

import org.slf4j.MDC;
import org.springframework.http.ProblemDetail;

import java.net.URI;
import java.util.UUID;

/** Builds every error body the same way (RFC 9457 Problem Details). */
public final class ProblemDetails {

    /** MDC key filled per request by the correlation-id filter. */
    public static final String REQUEST_ID_KEY = "requestId";

    private ProblemDetails() {
    }

    public static ProblemDetail of(ErrorCode code) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(code.status(), code.detail());
        problem.setType(code.type());
        problem.setTitle(code.title());
        problem.setProperty("code", code.name());
        String requestId = MDC.get(REQUEST_ID_KEY);
        if (requestId == null) {
            requestId = UUID.randomUUID().toString();
        }
        // The instance identifies this occurrence. It is NOT the request path, which would echo attacker input.
        problem.setInstance(URI.create("urn:swiftdrop:request:" + requestId));
        problem.setProperty(REQUEST_ID_KEY, requestId);
        return problem;
    }
}
