package com.swiftdrop.auth.common.web;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.SslOptions;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Found in production (lesson 17): the fail-fast customizer replaced Spring Boot's client options and with them
 * the TLS trust (our internal CA), so every Redis connection failed with "PKIX path building failed".
 */
class RateLimitStoreConfigTest {

    @Test
    void failFastKeepsTheTlsSettingsSpringBootAlreadyConfigured() {
        SslOptions bootTls = SslOptions.builder().jdkSslProvider().build();
        LettuceClientConfiguration.LettuceClientConfigurationBuilder builder = LettuceClientConfiguration.builder()
                .clientOptions(ClientOptions.builder().sslOptions(bootTls).build());

        new RateLimitStoreConfig().failFastWhileRedisIsDown().customize(builder);

        ClientOptions options = builder.build().getClientOptions().orElseThrow();
        assertThat(options.getSslOptions()).isSameAs(bootTls);
        assertThat(options.getDisconnectedBehavior()).isEqualTo(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS);
        assertThat(options.isAutoReconnect()).isTrue();
    }

    @Test
    void failFastAlsoWorksWithoutPreviousOptions() {
        LettuceClientConfiguration.LettuceClientConfigurationBuilder builder = LettuceClientConfiguration.builder();

        new RateLimitStoreConfig().failFastWhileRedisIsDown().customize(builder);

        assertThat(builder.build().getClientOptions().orElseThrow().getDisconnectedBehavior())
                .isEqualTo(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS);
    }
}
