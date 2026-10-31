package com.swiftdrop.auth.common.web;

import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.io.Writer;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Chunked uploads have no Content-Length: the limit must also be enforced while the body is read. */
class RequestSizeLimitFilterTest {

    private final HandlerExceptionResolver unusedResolver = (request, response, handler, ex) -> null;
    private final RequestSizeLimitFilter filter = new RequestSizeLimitFilter(unusedResolver);

    @Test
    void streamWithoutContentLengthIsCutOffAtTheLimit() throws Exception {
        HttpServletRequest chunked = withoutContentLength(new byte[RequestSizeLimitFilter.MAX_BODY_BYTES + 1]);
        ReadingChain chain = new ReadingChain();

        filter.doFilter(chunked, new MockHttpServletResponse(), chain);

        assertThat(chain.failure).isInstanceOf(PayloadTooLargeException.class);
    }

    @Test
    void streamWithinTheLimitIsReadNormally() throws Exception {
        HttpServletRequest chunked = withoutContentLength(new byte[RequestSizeLimitFilter.MAX_BODY_BYTES]);
        ReadingChain chain = new ReadingChain();

        filter.doFilter(chunked, new MockHttpServletResponse(), chain);

        assertThat(chain.failure).isNull();
        assertThat(chain.bytesRead).isEqualTo(RequestSizeLimitFilter.MAX_BODY_BYTES);
    }

    @Test
    void readingThroughGetReaderIsLimitedToo() throws Exception {
        HttpServletRequest chunked = withoutContentLength(new byte[RequestSizeLimitFilter.MAX_BODY_BYTES + 1]);
        AtomicReference<RuntimeException> failure = new AtomicReference<>();

        filter.doFilter(chunked, new MockHttpServletResponse(), (request, response) -> {
            try {
                request.getReader().transferTo(Writer.nullWriter());
            } catch (PayloadTooLargeException e) {
                failure.set(e);
            }
        });

        assertThat(failure.get()).isInstanceOf(PayloadTooLargeException.class);
    }

    @Test
    void declaredOversizedLengthNeverReachesTheChain() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/x");
        request.setContent(new byte[RequestSizeLimitFilter.MAX_BODY_BYTES + 1]);
        MockFilterChain chain = new MockFilterChain();

        assertThatThrownBy(() -> filter.doFilter(request, new MockHttpServletResponse(), chain))
                .isInstanceOf(PayloadTooLargeException.class);
        assertThat(chain.getRequest()).isNull();
    }

    private static HttpServletRequest withoutContentLength(byte[] body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/x");
        request.setContent(body);
        return new HttpServletRequestWrapper(request) {
            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public int getContentLength() {
                return -1;
            }
        };
    }

    private static final class ReadingChain extends MockFilterChain {
        private RuntimeException failure;
        private int bytesRead;

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response)
                throws IOException {
            ServletInputStream in = request.getInputStream();
            try {
                while (in.read() != -1) {
                    bytesRead++;
                }
            } catch (PayloadTooLargeException e) {
                failure = e;
            }
        }
    }
}
