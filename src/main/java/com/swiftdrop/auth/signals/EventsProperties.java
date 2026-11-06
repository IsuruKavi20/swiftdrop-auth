package com.swiftdrop.auth.signals;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code swiftdrop.events}: where identity events are pushed (identity step 6c). Events carry personal data, so a
 * receiver must be https (http only to localhost for development); a bad entry stops the start.
 */
@ConfigurationProperties("swiftdrop.events")
public record EventsProperties(Boolean pushEnabled, Duration pushInterval, List<Receiver> receivers) {

    public EventsProperties {
        pushEnabled = pushEnabled == null || pushEnabled;
        pushInterval = pushInterval == null ? Duration.ofSeconds(2) : pushInterval;
        receivers = receivers == null ? List.of() : List.copyOf(receivers);
        if (receivers.stream().map(Receiver::id).distinct().count() != receivers.size()) {
            throw new IllegalArgumentException("swiftdrop.events.receivers: duplicate id");
        }
    }

    /**
     * @param id       our name for the receiver (also its row in event_receivers)
     * @param audience the SET's "aud": what the receiver checks it is the intended recipient
     * @param pushUrl  RFC 8935 endpoint that accepts application/secevent+jwt
     */
    public record Receiver(String id, String audience, URI pushUrl) {

        private static final Pattern ID = Pattern.compile("^[a-z0-9-]{3,40}$");
        private static final Set<String> LOCAL = Set.of("localhost", "127.0.0.1");

        public Receiver {
            if (id == null || !ID.matcher(id).matches()) {
                throw new IllegalArgumentException("events receiver id: 3-40 of a-z, 0-9, -");
            }
            if (audience == null || audience.isBlank() || audience.length() > 100) {
                throw new IllegalArgumentException("events receiver audience is required");
            }
            if (pushUrl == null || !pushUrl.isAbsolute() || pushUrl.getHost() == null
                    || pushUrl.getRawUserInfo() != null) {
                throw new IllegalArgumentException("events receiver push-url must be an absolute URL without user info");
            }
            boolean https = "https".equals(pushUrl.getScheme());
            boolean localHttp = "http".equals(pushUrl.getScheme()) && LOCAL.contains(pushUrl.getHost());
            if (!https && !localHttp) {
                throw new IllegalArgumentException("events receiver push-url must use https");
            }
        }
    }
}
