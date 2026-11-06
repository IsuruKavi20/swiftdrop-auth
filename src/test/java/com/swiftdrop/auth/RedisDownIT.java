package com.swiftdrop.auth;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Redis goes away while the service runs: password login and rate limits keep working (lesson 16, 3c). */
class RedisDownIT {

    private static final PostgreSQLContainer postgres = TestcontainersConfiguration.newPostgresContainer();
    private static final GenericContainer<?> redis = TestcontainersConfiguration.newRedisContainer();
    private static final HttpClient http = HttpClient.newHttpClient();

    private static ConfigurableApplicationContext app;

    @BeforeAll
    static void startThenLoseRedis() {
        postgres.start();
        redis.start();
        Map<String, Object> properties = new HashMap<>(TestcontainersConfiguration.connectionProperties(postgres, redis));
        properties.put("server.port", 0);
        properties.put("spring.mail.host", "127.0.0.1");
        properties.put("spring.mail.port", 1);
        properties.put("spring.data.redis.timeout", "500ms");
        properties.put("swiftdrop.rate-limit.enabled", true);
        properties.put("swiftdrop.rate-limit.rules[0].name", "login");
        properties.put("swiftdrop.rate-limit.rules[0].method", "POST");
        properties.put("swiftdrop.rate-limit.rules[0].path", "/api/v1/auth/login");
        properties.put("swiftdrop.rate-limit.rules[0].per-minute", 2);
        app = new SpringApplicationBuilder(AuthApplication.class).profiles("test")
                // As command-line arguments: they win over application.yml (builder properties would not)
                .run(properties.entrySet().stream().map(e -> "--" + e.getKey() + "=" + e.getValue()).toArray(String[]::new));
        redis.stop();
    }

    @AfterAll
    static void stop() {
        if (app != null) {
            app.close();
        }
        postgres.stop();
    }

    @Test
    void loginStillAnswersAndTheLocalLimitTakesOver() throws Exception {
        assertThat(login().statusCode()).isEqualTo(401);   // wrong password, never 500
        assertThat(login().statusCode()).isEqualTo(401);
        assertThat(login().statusCode()).isEqualTo(429);   // this copy's own bucket
    }

    private static HttpResponse<String> login() throws Exception {
        int port = ((WebServerApplicationContext) app).getWebServer().getPort();
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/auth/login"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "{\"email\":\"nobody@example.com\",\"password\":\"whatever whatever\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
