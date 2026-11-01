package com.swiftdrop.auth.common.web;

import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.Bucket4jLettuce;
import io.lettuce.core.AbstractRedisClient;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulConnection;
import io.lettuce.core.cluster.RedisClusterClient;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Buckets in Redis, shared by every instance. Bucket4j updates a bucket with compare-and-swap (a Lua script):
 * two instances taking the last token at the same moment can't both win. Keys delete themselves once the
 * bucket is full again (plus a margin), so idle IPs cost no memory. Uses Spring's Redis settings (host,
 * password, TLS, timeouts); connects on first use, so the app also starts while Redis is down.
 */
final class RedisRateLimitStore implements RateLimitStore, AutoCloseable {

    static final String KEY_PREFIX = "swiftdrop:rl:";
    private static final Duration KEEP_FULL_BUCKETS_FOR = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofMillis(500);
    // While Redis is unreachable, requests don't each wait for a new connection attempt
    private static final Duration RECONNECT_PAUSE = Duration.ofSeconds(5);

    private final LettuceConnectionFactory connections;
    private final Clock clock;
    private volatile ProxyManager<String> buckets;
    private volatile StatefulConnection<String, byte[]> connection;
    private volatile Instant nextConnectAttempt = Instant.MIN;

    RedisRateLimitStore(LettuceConnectionFactory connections, Clock clock) {
        this.connections = connections;
        this.clock = clock;
    }

    static String redisKey(String key) {
        return KEY_PREFIX + key;
    }

    @Override
    public ConsumptionProbe tryConsume(String key, RateLimitProperties.Rule rule) {
        return buckets().builder()
                .build(redisKey(key), () -> RateLimitStore.configurationFor(rule))
                .tryConsumeAndReturnRemaining(1);
    }

    private ProxyManager<String> buckets() {
        ProxyManager<String> ready = buckets;
        if (ready != null) {
            return ready;
        }
        synchronized (this) {
            if (buckets == null) {
                if (clock.instant().isBefore(nextConnectAttempt)) {
                    throw new IllegalStateException("Redis unreachable, next connection attempt at " + nextConnectAttempt);
                }
                try {
                    buckets = connect();
                } catch (RuntimeException unreachable) {
                    nextConnectAttempt = clock.instant().plus(RECONNECT_PAUSE);
                    throw unreachable;
                }
            }
            return buckets;
        }
    }

    // After this first connection Lettuce reconnects by itself, e.g. when Redis restarts
    private ProxyManager<String> connect() {
        RedisCodec<String, byte[]> codec = RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE);
        AbstractRedisClient client = connections.getNativeClient();
        var builder = switch (client) {
            case RedisClient standalone -> {
                var opened = standalone.connect(codec);
                connection = opened;
                yield Bucket4jLettuce.casBasedBuilder(opened);
            }
            case RedisClusterClient cluster -> {
                var opened = cluster.connect(codec);
                connection = opened;
                yield Bucket4jLettuce.casBasedBuilder(opened);
            }
            default -> throw new IllegalStateException("Unsupported Redis client " + client.getClass().getName());
        };
        return builder
                .expirationAfterWrite(ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(KEEP_FULL_BUCKETS_FOR))
                .requestTimeout(REQUEST_TIMEOUT)
                .build();
    }

    /** Spring calls this on shutdown (inferred destroy method of the bean). */
    @Override
    public void close() {
        StatefulConnection<String, byte[]> open = connection;
        if (open != null) {
            open.close();
        }
    }
}
