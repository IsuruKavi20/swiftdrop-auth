package com.swiftdrop.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BreachedPasswordCheckConfigTest {

    private final BreachedPasswordCheckConfig config = new BreachedPasswordCheckConfig();

    @Test
    void productionRefusesToStartWithTheBreachCheckDisabled() {
        MockEnvironment prod = new MockEnvironment();
        prod.setActiveProfiles("prod");

        assertThatThrownBy(() -> config.breachCheckDisabled(prod))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("prod");
    }

    @Test
    void testsMayDisableIt() {
        MockEnvironment test = new MockEnvironment();
        test.setActiveProfiles("test");

        assertThat(config.breachCheckDisabled(test).check("anything").isCompromised()).isFalse();
    }
}
