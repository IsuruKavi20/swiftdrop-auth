package com.swiftdrop.auth.verification;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.Set;

/**
 * {@code swiftdrop.frontend.base-url}: where links in emails point. It comes from configuration and is
 * never built from the request's Host header (an attacker could otherwise make emails link to their site).
 * Must be https, except http://localhost for development.
 */
@ConfigurationProperties("swiftdrop.frontend")
public record FrontendProperties(URI baseUrl) {

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1");

    public FrontendProperties {
        if (baseUrl == null || baseUrl.getHost() == null) {
            throw new IllegalArgumentException("swiftdrop.frontend.base-url must be an absolute URL");
        }
        // "https://evil@good.com" puts misleading text before the real host in every emailed link
        if (baseUrl.getRawUserInfo() != null) {
            throw new IllegalArgumentException("swiftdrop.frontend.base-url must not contain user info");
        }
        boolean secure = "https".equals(baseUrl.getScheme());
        boolean localDevelopment = "http".equals(baseUrl.getScheme()) && LOCAL_HOSTS.contains(baseUrl.getHost());
        if (!secure && !localDevelopment) {
            throw new IllegalArgumentException("swiftdrop.frontend.base-url must use https");
        }
        boolean bare = (baseUrl.getPath() == null || baseUrl.getPath().isEmpty() || "/".equals(baseUrl.getPath()))
                && baseUrl.getQuery() == null && baseUrl.getFragment() == null;
        if (!bare) {
            throw new IllegalArgumentException("swiftdrop.frontend.base-url must not have a path, query or fragment");
        }
    }

    URI link(String path) {
        return URI.create(baseUrl.getScheme() + "://" + baseUrl.getRawAuthority() + path);
    }
}
