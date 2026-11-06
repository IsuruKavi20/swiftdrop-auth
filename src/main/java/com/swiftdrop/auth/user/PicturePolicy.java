package com.swiftdrop.auth.user;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

/**
 * Which profile photo links are allowed: only {@link ProfileProperties#pictureHosts() trusted image hosts}, on the
 * normal https port. Checked after {@link IdentityProfile}'s https/host/no-credentials rules.
 */
@Component
public class PicturePolicy {

    private static final int HTTPS_PORT = 443;

    private final List<String> rules;

    PicturePolicy(ProfileProperties properties) {
        this.rules = properties.pictureHosts();
    }

    public boolean isTrusted(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            boolean normalPort = uri.getPort() == -1 || uri.getPort() == HTTPS_PORT;
            return host != null && normalPort && rules.stream().anyMatch(rule -> matches(rule,
                    host.toLowerCase(Locale.ROOT)));
        } catch (URISyntaxException notAUrl) {
            return false;
        }
    }

    /** User input: an untrusted host is an error the user must fix. {@code null} (remove the photo) is fine. */
    public String requireTrusted(String url) {
        if (url != null && !isTrusted(url)) {
            throw new InvalidProfileException("picture", "TrustedHost");
        }
        return url;
    }

    /** Provider data (Google): an untrusted photo is dropped; the rest of the profile and the login go on. */
    public IdentityProfile trustedOnly(IdentityProfile profile) {
        return profile.pictureUrl().filter(url -> !isTrusted(url)).isPresent() ? profile.withoutPicture() : profile;
    }

    // ".example.com" = a sub-domain of example.com (the dot stops "evilexample.com"); "x.example.com" = exactly it
    private static boolean matches(String rule, String host) {
        return rule.startsWith(".") ? host.endsWith(rule) : host.equals(rule);
    }
}
