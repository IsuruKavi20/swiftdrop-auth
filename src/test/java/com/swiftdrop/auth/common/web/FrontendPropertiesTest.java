package com.swiftdrop.auth.common.web;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Email links are built from this setting, never from the request's Host header. */
class FrontendPropertiesTest {

    @Test
    void httpsIsAccepted() {
        assertThat(new FrontendProperties(URI.create("https://app.swiftdrop.dev")).baseUrl()).isNotNull();
    }

    @Test
    void plainHttpIsOnlyAllowedForLocalhost() {
        assertThat(new FrontendProperties(URI.create("http://localhost:3000")).baseUrl()).isNotNull();

        assertThatThrownBy(() -> new FrontendProperties(URI.create("http://app.swiftdrop.dev")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void urlWithPathQueryOrFragmentIsRejected() {
        assertThatThrownBy(() -> new FrontendProperties(URI.create("https://app.swiftdrop.dev/x?y=1")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void urlWithUserInfoIsRejected() {
        assertThatThrownBy(() -> new FrontendProperties(URI.create("https://evil@app.swiftdrop.dev")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
