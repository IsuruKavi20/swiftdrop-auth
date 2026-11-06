package com.swiftdrop.auth.common.web;

import io.lettuce.core.ClientOptions;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.data.redis.autoconfigure.LettuceClientConfigurationBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.time.Clock;

/** {@code swiftdrop.rate-limit.store}: {@code redis} (shared, with local fallback) or {@code local}. */
@Configuration(proxyBeanMethods = false)
class RateLimitStoreConfig {

    // While disconnected, Redis commands fail at once instead of queueing up and each waiting for a timeout.
    // Changes Spring Boot's options instead of replacing them: they carry the TLS trust (our internal CA)
    @Bean
    LettuceClientConfigurationBuilderCustomizer failFastWhileRedisIsDown() {
        return builder -> {
            ClientOptions current = builder.build().getClientOptions().orElseGet(ClientOptions::create);
            builder.clientOptions(current.mutate()
                    .autoReconnect(true)
                    .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)
                    .build());
        };
    }

    @Bean
    RateLimitStore rateLimitStore(RateLimitProperties properties, ObjectProvider<LettuceConnectionFactory> redis) {
        LocalRateLimitStore local = new LocalRateLimitStore(properties.maxTrackedKeys());
        if (properties.store() == RateLimitProperties.Store.LOCAL) {
            return local;
        }
        LettuceConnectionFactory connections = redis.getIfAvailable();
        if (connections == null) {
            throw new IllegalStateException("swiftdrop.rate-limit.store=redis needs spring.data.redis.* settings");
        }
        return new FallbackRateLimitStore(new RedisRateLimitStore(connections, Clock.systemUTC()), local);
    }
}
