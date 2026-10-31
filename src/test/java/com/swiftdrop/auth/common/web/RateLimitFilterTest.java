package com.swiftdrop.auth.common.web;

import com.swiftdrop.auth.common.error.RateLimitedException;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Per-IP token buckets in front of the public endpoints (deep dive 26, section 3). */
class RateLimitFilterTest {

    private final HandlerExceptionResolver resolver = mock(HandlerExceptionResolver.class);
    private final FilterChain chain = mock(FilterChain.class);

    private RateLimitFilter filter(boolean enabled, int loginPerMinute) {
        when(resolver.resolveException(any(), any(), isNull(), any())).thenReturn(new ModelAndView());
        return new RateLimitFilter(new RateLimitProperties(enabled, 1000,
                List.of(new RateLimitProperties.Rule("login", "POST", "/api/v1/auth/login", loginPerMinute))), resolver);
    }

    @Test
    void requestsAboveTheLimitGet429WithRetryAfter() throws Exception {
        RateLimitFilter filter = filter(true, 3);
        for (int i = 0; i < 3; i++) {
            filter.doFilter(login("203.0.113.7"), new MockHttpServletResponse(), chain);
        }

        filter.doFilter(login("203.0.113.7"), new MockHttpServletResponse(), chain);

        verify(chain, times(3)).doFilter(any(), any());
        verify(resolver).resolveException(any(), any(), isNull(),
                org.mockito.ArgumentMatchers.argThat(e -> e instanceof RateLimitedException limited
                        && limited.retryAfterSeconds() >= 1 && limited.retryAfterSeconds() <= 60));
    }

    @Test
    void anEncodedPathCannotSlipPastTheLimit() throws Exception {
        RateLimitFilter filter = filter(true, 1);
        filter.doFilter(login("203.0.113.7"), new MockHttpServletResponse(), chain);

        MockHttpServletRequest encoded = new MockHttpServletRequest("POST", "/api/v1/auth/log%69n");
        encoded.setRemoteAddr("203.0.113.7");
        filter.doFilter(encoded, new MockHttpServletResponse(), chain);

        verify(chain, times(1)).doFilter(any(), any());   // "/log%69n" is "/login": same bucket, limited
    }

    @Test
    void oneIpv6NetworkIsOneClient() {
        assertThat(RateLimitFilter.clientKey("2001:db8:1:2::1")).isEqualTo(RateLimitFilter.clientKey("2001:db8:1:2:ffff::9"));
        assertThat(RateLimitFilter.clientKey("2001:db8:1:2::1")).isNotEqualTo(RateLimitFilter.clientKey("2001:db8:1:3::1"));
        assertThat(RateLimitFilter.clientKey("::ffff:203.0.113.7")).isEqualTo("203.0.113.7");
        assertThat(RateLimitFilter.clientKey("203.0.113.7")).isEqualTo("203.0.113.7");
    }

    @Test
    void eachIpHasItsOwnBucket() throws Exception {
        RateLimitFilter filter = filter(true, 1);
        filter.doFilter(login("203.0.113.7"), new MockHttpServletResponse(), chain);

        filter.doFilter(login("198.51.100.9"), new MockHttpServletResponse(), chain);

        verify(chain, times(2)).doFilter(any(), any());
        verify(resolver, never()).resolveException(any(), any(), any(), any());
    }

    @Test
    void otherEndpointsAndMethodsAreNotLimitedByThisRule() throws Exception {
        RateLimitFilter filter = filter(true, 1);
        filter.doFilter(login("203.0.113.7"), new MockHttpServletResponse(), chain);

        MockHttpServletRequest getLogin = login("203.0.113.7");
        getLogin.setMethod("GET");
        filter.doFilter(getLogin, new MockHttpServletResponse(), chain);
        MockHttpServletRequest jwks = new MockHttpServletRequest("GET", "/.well-known/jwks.json");
        jwks.setRemoteAddr("203.0.113.7");
        filter.doFilter(jwks, new MockHttpServletResponse(), chain);

        verify(chain, times(3)).doFilter(any(), any());
    }

    @Test
    void switchedOffMeansNoLimits() throws Exception {
        RateLimitFilter filter = filter(false, 1);
        for (int i = 0; i < 5; i++) {
            filter.doFilter(login("203.0.113.7"), new MockHttpServletResponse(), chain);
        }

        verify(chain, times(5)).doFilter(any(), any());
    }

    @Test
    void badConfigurationIsRefusedAtStartup() {
        assertThatThrownBy(() -> new RateLimitProperties(true, 1000,
                List.of(new RateLimitProperties.Rule("login", "POST", "api/no-slash", 10))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RateLimitProperties(true, 1000,
                List.of(new RateLimitProperties.Rule("login", "POST", "/x", 0))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RateLimitProperties(true, 0, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rulesMatchTheExactPathNotPrefixes() {
        RateLimitProperties.Rule rule = new RateLimitProperties.Rule("login", "POST", "/api/v1/auth/login", 1);
        assertThat(rule.matches("POST", "/api/v1/auth/login")).isTrue();
        assertThat(rule.matches("POST", "/api/v1/auth/login-other")).isFalse();
        assertThat(rule.matches("post", "/api/v1/auth/login")).isTrue();
    }

    private static MockHttpServletRequest login(String ip) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr(ip);
        return request;
    }
}
