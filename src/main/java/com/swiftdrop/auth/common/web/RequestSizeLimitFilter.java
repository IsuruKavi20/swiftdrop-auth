package com.swiftdrop.auth.common.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Rejects request bodies larger than {@link #MAX_BODY_BYTES} with 413. Tomcat only limits form posts,
 * not JSON, so we enforce it ourselves: by the declared Content-Length up front, and by counting bytes
 * while the body is read (chunked uploads have no Content-Length). Both getInputStream() and getReader()
 * go through the counter. Form and multipart parsing are capped in application.yml (multipart is disabled).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RequestSizeLimitFilter extends OncePerRequestFilter {

    /** Our JSON requests are a few hundred bytes; 16 KB leaves plenty of room. */
    public static final int MAX_BODY_BYTES = 16 * 1024;

    private final HandlerExceptionResolver resolver;

    public RequestSizeLimitFilter(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getContentLengthLong() > MAX_BODY_BYTES) {
            PayloadTooLargeException tooLarge = new PayloadTooLargeException();
            if (resolver.resolveException(request, response, null, tooLarge) == null) {
                throw tooLarge;
            }
            return;
        }
        chain.doFilter(new SizeLimitedRequest(request), response);
    }

    private static final class SizeLimitedRequest extends HttpServletRequestWrapper {

        private ServletInputStream limited;

        SizeLimitedRequest(HttpServletRequest request) {
            super(request);
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (limited == null) {
                limited = new SizeLimitedInputStream(super.getInputStream());
            }
            return limited;
        }

        // Without this, code reading the body as text would bypass the limit
        @Override
        public BufferedReader getReader() throws IOException {
            String encoding = getCharacterEncoding();
            Charset charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    private static final class SizeLimitedInputStream extends ServletInputStream {

        private final ServletInputStream delegate;
        private long bytesRead;

        SizeLimitedInputStream(ServletInputStream delegate) {
            this.delegate = delegate;
        }

        @Override
        public int read() throws IOException {
            int value = delegate.read();
            if (value != -1) {
                count(1);
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int read = delegate.read(buffer, offset, length);
            if (read > 0) {
                count(read);
            }
            return read;
        }

        private void count(int bytes) {
            bytesRead += bytes;
            if (bytesRead > MAX_BODY_BYTES) {
                throw new PayloadTooLargeException();
            }
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            delegate.setReadListener(listener);
        }
    }
}
