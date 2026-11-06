package com.swiftdrop.auth.common.web;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.data.redis.autoconfigure.DataRedisProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Production Redis must need a password and use TLS: an empty REDIS_PASSWORD resolves to "" (not a startup
 * error), so it is checked here. No password or no TLS, no startup.
 */
@Component
@Profile("prod")
class RedisSafetyCheck implements InitializingBean {

    private final DataRedisProperties redis;

    RedisSafetyCheck(DataRedisProperties redis) {
        this.redis = redis;
    }

    @Override
    public void afterPropertiesSet() {
        if (redis.getPassword() == null || redis.getPassword().isBlank()) {
            throw new IllegalStateException("Production Redis needs a password: set REDIS_PASSWORD");
        }
        if (!redis.getSsl().isEnabled()) {
            throw new IllegalStateException("Production Redis must use TLS: spring.data.redis.ssl.enabled=true");
        }
    }
}
