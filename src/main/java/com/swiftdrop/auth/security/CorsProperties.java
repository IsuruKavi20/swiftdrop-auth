package com.swiftdrop.auth.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * {@code swiftdrop.cors.allowed-origins}: the exact frontend addresses (scheme://host[:port]) whose browser code may
 * call this API. Never "*", https only (http just for localhost development), validated at startup.
 * Empty = no browser access from other origins (fail closed).
 */
@ConfigurationProperties("swiftdrop.cors")
public record CorsProperties(List<String> allowedOrigins) {

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1");

    public CorsProperties {
        allowedOrigins = allowedOrigins == null ? List.of()
                : allowedOrigins.stream().filter(origin -> origin != null && !origin.isBlank()).toList();
        allowedOrigins.forEach(CorsProperties::validate);
    }

    private static void validate(String origin) {
        if (origin.contains("*")) {
            throw new IllegalArgumentException("swiftdrop.cors.allowed-origins: wildcards are not allowed: " + origin);
        }
        URI uri;
        try {
            uri = URI.create(origin);
        } catch (IllegalArgumentException malformed) {
            throw new IllegalArgumentException("swiftdrop.cors.allowed-origins: not a valid URL: " + origin, malformed);
        }
        boolean bare = (uri.getRawPath() == null || uri.getRawPath().isEmpty())
                && uri.getRawQuery() == null && uri.getRawFragment() == null && uri.getRawUserInfo() == null;
        if (uri.getHost() == null || !bare) {
            throw new IllegalArgumentException(
                    "swiftdrop.cors.allowed-origins: use exactly scheme://host[:port], nothing else: " + origin);
        }
        boolean secure = "https".equals(uri.getScheme());
        boolean localDevelopment = "http".equals(uri.getScheme()) && LOCAL_HOSTS.contains(uri.getHost());
        if (!secure && !localDevelopment) {
            throw new IllegalArgumentException("swiftdrop.cors.allowed-origins: must use https: " + origin);
        }
    }
}
