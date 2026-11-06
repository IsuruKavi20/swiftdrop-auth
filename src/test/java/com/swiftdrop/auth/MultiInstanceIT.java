package com.swiftdrop.auth;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Two real copies of the service (A and B) on their own ports, sharing one Postgres and one Redis, like two
 * instances behind a load balancer. Proves that what one copy knows, the other knows too (lesson 16).
 */
class MultiInstanceIT {

    private static final String LOGIN_COOKIE = "SWIFTDROP_LOGIN";
    private static final String AUTHORIZATION_REQUEST =
            "org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository.AUTHORIZATION_REQUEST";
    private static final String BROWSER_CHALLENGE = "swiftdrop.google.browser-challenge";
    // RFC 7636 appendix B example challenge
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static final PostgreSQLContainer postgres = TestcontainersConfiguration.newPostgresContainer();
    private static final GenericContainer<?> redis = TestcontainersConfiguration.newRedisContainer();
    private static final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private static ConfigurableApplicationContext copyA;
    private static ConfigurableApplicationContext copyB;

    @BeforeAll
    static void startTwoCopies() {
        postgres.start();
        redis.start();
        copyA = startCopy();
        copyB = startCopy();
    }

    @AfterAll
    static void stopEverything() {
        if (copyB != null) {
            copyB.close();
        }
        if (copyA != null) {
            copyA.close();
        }
        redis.stop();
        postgres.stop();
    }

    static ConfigurableApplicationContext startCopy() {
        Map<String, Object> properties = new HashMap<>(TestcontainersConfiguration.connectionProperties(postgres, redis));
        properties.put("server.port", 0);
        properties.put("spring.mail.host", "127.0.0.1");
        properties.put("spring.mail.port", 1);   // nothing here sends mail
        properties.put("swiftdrop.rate-limit.enabled", true);
        properties.put("swiftdrop.rate-limit.rules[0].name", "login");
        properties.put("swiftdrop.rate-limit.rules[0].method", "POST");
        properties.put("swiftdrop.rate-limit.rules[0].path", "/api/v1/auth/login");
        properties.put("swiftdrop.rate-limit.rules[0].per-minute", 2);
        return new SpringApplicationBuilder(AuthApplication.class).profiles("test")
                // As command-line arguments: they win over application.yml (builder properties would not)
                .run(properties.entrySet().stream().map(e -> "--" + e.getKey() + "=" + e.getValue()).toArray(String[]::new));
    }

    @Test
    void theLoginLimitIsSharedByBothCopies() throws Exception {
        assertThat(login(copyA).statusCode()).isEqualTo(401);
        assertThat(login(copyB).statusCode()).isEqualTo(401);

        // Limit 2 per minute for the IP: per copy it would be 4 in total, shared it is 2
        HttpResponse<String> third = login(copyA);
        assertThat(third.statusCode()).isEqualTo(429);
        assertThat(third.headers().firstValue("Retry-After")).isPresent();
        assertThat(login(copyB).statusCode()).isEqualTo(429);
    }

    @Test
    @SuppressWarnings("unchecked")
    void aGoogleLoginStartedOnCopyACanFinishOnCopyB() throws Exception {
        HttpResponse<String> start = http.send(HttpRequest.newBuilder(
                        url(copyA, "/oauth2/authorization/google?code_challenge=" + CHALLENGE)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(start.statusCode()).isEqualTo(302);
        String sessionId = sessionIdFrom(start);

        // Google would send the browser back to whichever copy the load balancer picks: here B
        SessionRepository<Session> sessionsOnB = copyB.getBean(SessionRepository.class);
        Session session = sessionsOnB.findById(sessionId);

        assertThat(session).as("copy B sees the session copy A created").isNotNull();
        assertThat((Object) session.getAttribute(AUTHORIZATION_REQUEST)).isNotNull();
        assertThat((Object) session.getAttribute(BROWSER_CHALLENGE))
                .isEqualTo(CHALLENGE);
    }

    private static HttpResponse<String> login(ConfigurableApplicationContext copy) throws Exception {
        return http.send(HttpRequest.newBuilder(url(copy, "/api/v1/auth/login"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "{\"email\":\"nobody@example.com\",\"password\":\"whatever whatever\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static URI url(ConfigurableApplicationContext copy, String path) {
        int port = ((WebServerApplicationContext) copy).getWebServer().getPort();
        return URI.create("http://127.0.0.1:" + port + path);
    }

    // Spring Session's cookie value is the session id, Base64-encoded
    private static String sessionIdFrom(HttpResponse<?> response) {
        String cookie = response.headers().allValues("Set-Cookie").stream()
                .filter(header -> header.startsWith(LOGIN_COOKIE + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no " + LOGIN_COOKIE + " cookie"));
        String value = cookie.substring(LOGIN_COOKIE.length() + 1, cookie.indexOf(';'));
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
