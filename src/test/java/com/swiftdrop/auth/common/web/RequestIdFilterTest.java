package com.swiftdrop.auth.common.web;

import com.swiftdrop.auth.common.error.ProblemDetails;
import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class RequestIdFilterTest {

    private final RequestIdFilter filter = new RequestIdFilter();

    @Test
    void errorDispatchReusesTheOriginalRequestId() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/x");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        String original = (String) request.getAttribute(RequestIdFilter.ATTRIBUTE);

        // The container forwards the same request to /error after something failed
        request.setDispatcherType(DispatcherType.ERROR);
        AtomicReference<String> seenInMdc = new AtomicReference<>();
        filter.doFilter(request, new MockHttpServletResponse(),
                (req, res) -> seenInMdc.set(MDC.get(ProblemDetails.REQUEST_ID_KEY)));

        assertThat(seenInMdc.get()).isEqualTo(original);
    }

    @Test
    void mdcIsClearedAfterTheRequest() throws Exception {
        filter.doFilter(new MockHttpServletRequest("GET", "/api/v1/x"), new MockHttpServletResponse(),
                new MockFilterChain());

        assertThat(MDC.get(ProblemDetails.REQUEST_ID_KEY)).isNull();
    }
}
