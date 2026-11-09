package com.swiftdrop.auth.signup;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** An outbox event stored BEFORE frontends existed (no frontendId) is still read: its email goes to the primary app. */
class AccountRegisteredCompatibilityTest {

    @Test
    void anOldEventWithoutFrontendIdIsStillRead() {
        UUID user = UUID.randomUUID();

        AccountRegistered old = JsonMapper.builder().build()
                .readValue("{\"userId\":\"" + user + "\"}", AccountRegistered.class);

        assertThat(old.userId()).isEqualTo(user);
        assertThat(old.frontendId()).isNull();
    }
}
