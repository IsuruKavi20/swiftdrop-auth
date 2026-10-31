package com.swiftdrop.auth.common.web;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.swiftdrop.auth.common.error.RateLimitedException;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.util.UrlPathHelper;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HexFormat;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Per-IP token buckets in front of the public endpoints: N requests per minute per client IP and endpoint,
 * then 429 + Retry-After. Runs right after the request id, before security and any expensive work (Argon2).
 * The client IP is {@code getRemoteAddr()}: behind a load balancer, prod makes Tomcat take it from the
 * trusted proxy's X-Forwarded-For (server.forward-headers-strategy), never from a header the client invents.
 * Buckets live in memory, per instance; several instances need a shared store (Redis), see deep dive 26.
 */
@Component
// Registers its own settings, so web slice tests (which pick up filters) can create it too; unset = switched off
@EnableConfigurationProperties(RateLimitProperties.class)
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final Duration FORGET_IDLE_KEYS_AFTER = Duration.ofMinutes(15);
    private static final int IPV6_PREFIX_BYTES = 8;   // one /64 network = one client
    // Decoded + normalised like Spring MVC sees it (%69 → i, ;jsessionid removed, // collapsed): no encoding bypass
    private static final UrlPathHelper PATHS = new UrlPathHelper();

    private final RateLimitProperties properties;
    private final HandlerExceptionResolver resolver;
    private final Cache<String, Bucket> buckets;

    public RateLimitFilter(RateLimitProperties properties,
                           @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.properties = properties;
        this.resolver = resolver;
        this.buckets = Caffeine.newBuilder()
                .maximumSize(properties.maxTrackedKeys())
                .expireAfterAccess(FORGET_IDLE_KEYS_AFTER)
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        RateLimitProperties.Rule rule = properties.enabled() ? ruleFor(request) : null;
        if (rule != null) {
            Bucket bucket = buckets.get(rule.name() + "|" + clientKey(request.getRemoteAddr()), key -> newBucket(rule));
            ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
            if (!probe.isConsumed()) {
                long waitSeconds = TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()) + 1;
                RateLimitedException limited = new RateLimitedException(waitSeconds);
                // Same Problem Details + Retry-After as every other error (GlobalExceptionHandler)
                if (resolver.resolveException(request, response, null, limited) == null) {
                    throw limited;
                }
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private RateLimitProperties.Rule ruleFor(HttpServletRequest request) {
        String path = PATHS.getPathWithinApplication(request);
        for (RateLimitProperties.Rule rule : properties.rules()) {
            if (rule.matches(request.getMethod(), path)) {
                return rule;
            }
        }
        return null;
    }

    /**
     * IPv4: the address. IPv6: its /64 network (one customer usually owns a whole /64, so per-address buckets
     * would be unlimited). IPv4-mapped IPv6 (::ffff:1.2.3.4) is parsed by Java as plain IPv4.
     */
    static String clientKey(String remoteAddr) {
        try {
            InetAddress address = InetAddress.getByName(remoteAddr);   // a numeric literal: no DNS lookup happens
            if (address instanceof Inet6Address) {
                byte[] network = java.util.Arrays.copyOf(address.getAddress(), IPV6_PREFIX_BYTES);
                return HexFormat.of().formatHex(network) + "::/64";
            }
            return address.getHostAddress();
        } catch (UnknownHostException | SecurityException unparsable) {
            return remoteAddr;
        }
    }

    // Greedy refill: tokens come back smoothly over the minute, not all at once at the end
    private static Bucket newBucket(RateLimitProperties.Rule rule) {
        return Bucket.builder()
                .addLimit(limit -> limit.capacity(rule.perMinute()).refillGreedy(rule.perMinute(), WINDOW))
                .build();
    }
}
