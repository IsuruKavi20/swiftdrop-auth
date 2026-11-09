package com.swiftdrop.auth.common.web;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code swiftdrop.frontends}: the registered frontends (the SwiftDrop app online, on developers' laptops). The ONLY
 * places users are ever sent to (email links, the end of Google login) and the ONLY origins allowed by CORS.
 * A request can name one (an id) or come from one (an Origin that matches exactly); it can never supply an address,
 * so there is no open redirect (RFC 6749 3.1.2, RFC 9700 4.1, OWASP). Unknown or missing = the primary frontend.
 * Checked at startup: https (http only for localhost), a bare scheme://host[:port], unique ids, exactly one primary.
 */
@ConfigurationProperties("swiftdrop")
public record FrontendRegistry(List<Frontend> frontends) {

    public FrontendRegistry {
        if (frontends == null || frontends.isEmpty()) {
            throw new IllegalArgumentException("swiftdrop.frontends: at least one frontend is required");
        }
        frontends = List.copyOf(frontends);
        if (frontends.stream().map(Frontend::id).distinct().count() != frontends.size()) {
            throw new IllegalArgumentException("swiftdrop.frontends: duplicate id");
        }
        if (frontends.stream().filter(Frontend::primary).count() != 1) {
            throw new IllegalArgumentException("swiftdrop.frontends: exactly one must be primary: true");
        }
    }

    /** {@code path} (with fragment) on the named frontend; unknown or null id = the primary one. */
    public URI link(String frontendId, String path) {
        return byId(frontendId).orElseGet(this::primary).link(path);
    }

    /** The id of the frontend whose origin is EXACTLY this one (the browser's Origin header), if any. */
    public Optional<String> idForOrigin(String origin) {
        return frontends.stream().filter(frontend -> frontend.origin().equals(origin)).map(Frontend::id).findFirst();
    }

    /** True when the id names a registered frontend. */
    public boolean isKnown(String frontendId) {
        return byId(frontendId).isPresent();
    }

    /** For CORS: exactly the registered origins. */
    public List<String> origins() {
        return frontends.stream().map(Frontend::origin).toList();
    }

    private Optional<Frontend> byId(String frontendId) {
        return frontends.stream().filter(frontend -> frontend.id().equals(frontendId)).findFirst();
    }

    private Frontend primary() {
        return frontends.stream().filter(Frontend::primary).findFirst().orElseThrow();
    }

    /**
     * @param id      short name the frontend uses for itself (e.g. {@code web}, {@code local})
     * @param baseUrl scheme://host[:port], nothing else
     * @param primary used when we can't know which frontend the person came from
     */
    public record Frontend(String id, URI baseUrl, boolean primary) {

        private static final Pattern ID = Pattern.compile("^[a-z0-9-]{2,30}$");
        private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1");

        public Frontend {
            if (id == null || !ID.matcher(id).matches()) {
                throw new IllegalArgumentException("swiftdrop.frontends id: 2-30 of a-z, 0-9, -");
            }
            if (baseUrl == null || baseUrl.getHost() == null || !baseUrl.isAbsolute()) {
                throw new IllegalArgumentException("swiftdrop.frontends." + id + ": base-url must be an absolute URL");
            }
            // "https://evil@good.com" puts misleading text before the real host in every emailed link
            boolean bare = baseUrl.getRawUserInfo() == null && baseUrl.getRawQuery() == null
                    && baseUrl.getRawFragment() == null
                    && (baseUrl.getRawPath() == null || baseUrl.getRawPath().isEmpty());
            if (!bare) {
                throw new IllegalArgumentException("swiftdrop.frontends." + id + ": base-url must be scheme://host[:port]");
            }
            // Written exactly the way browsers send Origin (lowercase, no default port), or it would never match
            boolean defaultPort = baseUrl.getPort() == 443 && "https".equalsIgnoreCase(baseUrl.getScheme())
                    || baseUrl.getPort() == 80 && "http".equalsIgnoreCase(baseUrl.getScheme());
            if (!baseUrl.toString().equals(baseUrl.toString().toLowerCase(java.util.Locale.ROOT)) || defaultPort) {
                throw new IllegalArgumentException("swiftdrop.frontends." + id
                        + ": base-url must be lowercase and without a default port (as browsers send Origin)");
            }
            boolean secure = "https".equals(baseUrl.getScheme());
            boolean localDevelopment = "http".equals(baseUrl.getScheme()) && LOCAL_HOSTS.contains(baseUrl.getHost());
            if (!secure && !localDevelopment) {
                throw new IllegalArgumentException("swiftdrop.frontends." + id + ": base-url must use https");
            }
        }

        String origin() {
            return baseUrl.getScheme() + "://" + baseUrl.getRawAuthority();
        }

        URI link(String path) {
            return URI.create(origin() + path);
        }
    }
}
