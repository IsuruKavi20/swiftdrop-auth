package com.swiftdrop.auth.signals;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A bad event receiver must stop the start: events carry personal data and must only go where intended. */
class EventsPropertiesTest {

    @Test
    void acceptsAnHttpsReceiverAndLocalhostForDevelopment() {
        assertThat(receiver("https://api.getswiftdrop.me/internal/identity-events").pushUrl().getHost())
                .isEqualTo("api.getswiftdrop.me");
        assertThat(receiver("http://localhost:8081/internal/identity-events").pushUrl().getPort()).isEqualTo(8081);
    }

    @Test
    void refusesPlainHttpToAnyOtherHost() {
        assertThatThrownBy(() -> receiver("http://api.getswiftdrop.me/events"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesUserInfoInThePushUrl() {
        assertThatThrownBy(() -> receiver("https://user:pass@api.getswiftdrop.me/events"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesBadIdsAndDuplicates() {
        assertThatThrownBy(() -> new EventsProperties.Receiver("Bad Id!", "swiftdrop-backend",
                URI.create("https://x.example/e"))).isInstanceOf(IllegalArgumentException.class);
        EventsProperties.Receiver one = receiver("https://x.example/e");
        assertThatThrownBy(() -> new EventsProperties(true, Duration.ofSeconds(2), List.of(one, one)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sensibleDefaults() {
        EventsProperties defaults = new EventsProperties(null, null, null);

        assertThat(defaults.pushEnabled()).isTrue();
        assertThat(defaults.pushInterval()).isEqualTo(Duration.ofSeconds(2));
        assertThat(defaults.receivers()).isEmpty();
    }

    private static EventsProperties.Receiver receiver(String url) {
        return new EventsProperties.Receiver("swiftdrop-backend", "swiftdrop-backend", URI.create(url));
    }
}
