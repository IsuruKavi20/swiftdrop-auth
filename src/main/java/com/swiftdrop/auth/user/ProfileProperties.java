package com.swiftdrop.auth.user;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * {@code swiftdrop.profile.picture-hosts}: the image hosts a profile photo may point at. Photos are shown to other
 * people, so a photo on the user's own server would work like a tracking pixel (it reveals when and from where
 * others look). A rule starting with a dot ({@code .googleusercontent.com}) allows that domain's sub-domains; any
 * other rule is one exact host. No wildcards, schemes or paths: a bad rule stops the start.
 */
@ConfigurationProperties("swiftdrop.profile")
public record ProfileProperties(List<String> pictureHosts) {

    private static final Pattern HOST = Pattern.compile("\\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*");

    public ProfileProperties {
        pictureHosts = pictureHosts == null ? List.of()
                : pictureHosts.stream().map(rule -> rule == null ? "" : rule.strip().toLowerCase(Locale.ROOT)).toList();
        for (String rule : pictureHosts) {
            if (!HOST.matcher(rule).matches()) {
                throw new IllegalArgumentException("swiftdrop.profile.picture-hosts: not a host name rule");
            }
        }
    }
}
