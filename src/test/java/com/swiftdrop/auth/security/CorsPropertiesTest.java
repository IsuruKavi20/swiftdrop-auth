package com.swiftdrop.auth.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A wrong CORS setting stops the app at startup instead of quietly opening it to other sites. */
class CorsPropertiesTest {

    @Test
    void exactOriginsAreAccepted() {
        assertThat(new CorsProperties(List.of("http://localhost:5173", "https://app.swiftdrop.dev")).allowedOrigins())
                .containsExactly("http://localhost:5173", "https://app.swiftdrop.dev");
    }

    @Test
    void wildcardsAreRefused() {
        assertThatThrownBy(() -> new CorsProperties(List.of("*"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CorsProperties(List.of("https://*.swiftdrop.dev")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void plainHttpOnlyForLocalhost() {
        assertThatThrownBy(() -> new CorsProperties(List.of("http://app.swiftdrop.dev")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anOriginHasNoPathQueryOrUserInfo() {
        assertThatThrownBy(() -> new CorsProperties(List.of("https://app.swiftdrop.dev/login")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CorsProperties(List.of("https://evil@app.swiftdrop.dev")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nothingConfiguredMeansNoBrowserAccess() {
        assertThat(new CorsProperties(null).allowedOrigins()).isEmpty();
    }
}
