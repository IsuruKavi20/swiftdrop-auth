package com.swiftdrop.auth.session;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;

class SessionPropertiesTest {

    @Test
    void chosenDefaultsAreValid() {
        assertThatNoException().isThrownBy(() -> new SessionProperties(Duration.ofDays(1), Duration.ofDays(7)));
    }

    @Test
    void idleLongerThanAbsoluteMakesNoSense() {
        assertThatThrownBy(() -> new SessionProperties(Duration.ofDays(8), Duration.ofDays(7)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void missingZeroOrHugeValuesAreRefusedAtStartup() {
        assertThatThrownBy(() -> new SessionProperties(null, Duration.ofDays(7))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SessionProperties(Duration.ZERO, Duration.ofDays(7))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SessionProperties(Duration.ofDays(1), Duration.ofDays(91))).isInstanceOf(IllegalArgumentException.class);
    }
}
