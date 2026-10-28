package com.swiftdrop.auth.google;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The brief requires Google login, so production must not start without it; development may. */
class GoogleLoginSafetyCheckTest {

    @Test
    void productionWithoutGoogleClientRefusesToStart() {
        assertThatThrownBy(() -> new GoogleLoginSafetyCheck(new GoogleProperties("", "", null)).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("GOOGLE_CLIENT_ID");
    }

    @Test
    void productionWithGoogleClientStarts() {
        assertThatCode(() -> new GoogleLoginSafetyCheck(new GoogleProperties("id.apps.googleusercontent.com", "secret",
                java.net.URI.create("https://auth.swiftdrop.dev"))).afterPropertiesSet()).doesNotThrowAnyException();
    }

    @Test
    void productionMustPinTheHttpsAddressGoogleRedirectsBackTo() {
        assertThatThrownBy(() -> new GoogleLoginSafetyCheck(new GoogleProperties("id", "secret", null)).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("SWIFTDROP_PUBLIC_BASE_URL");
        assertThatThrownBy(() -> new GoogleLoginSafetyCheck(new GoogleProperties("id", "secret",
                java.net.URI.create("http://auth.swiftdrop.dev"))).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void enabledOnlyWhenBothValuesArePresent() {
        assertThat(new GoogleProperties("id", "secret", null).enabled()).isTrue();
        assertThat(new GoogleProperties("id", " ", null).enabled()).isFalse();
        assertThat(new GoogleProperties(null, "secret", null).enabled()).isFalse();
    }

    @Test
    void secretNeverAppearsInToString() {
        assertThat(new GoogleProperties("id", "super-secret", null).toString()).doesNotContain("super-secret");
    }
}
