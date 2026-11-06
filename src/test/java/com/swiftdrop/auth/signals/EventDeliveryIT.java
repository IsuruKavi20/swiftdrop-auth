package com.swiftdrop.auth.signals;

import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Identity step 6c: pushing signed events to a receiver (RFC 8935) over real HTTP, with retries, dead events and
 * two senders at once. The receiver is a tiny HTTP server inside this test; each test decides what it answers.
 */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class EventDeliveryIT {

    private static final HttpServer RECEIVER;
    private static final AtomicInteger ANSWER = new AtomicInteger(202);
    private static final List<Map<String, String>> RECEIVED = new CopyOnWriteArrayList<>();

    static {
        try {
            RECEIVER = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        RECEIVER.createContext("/identity-events", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            RECEIVED.add(Map.of("contentType", String.valueOf(exchange.getRequestHeaders().getFirst("Content-Type")),
                    "body", body));
            int status = ANSWER.get();
            byte[] answer = status == 400 ? "{\"err\":\"invalid_request\"}".getBytes(StandardCharsets.UTF_8)
                    : new byte[0];
            exchange.sendResponseHeaders(status, answer.length == 0 ? -1 : answer.length);
            exchange.getResponseBody().write(answer);
            exchange.close();
        });
        RECEIVER.setExecutor(Executors.newFixedThreadPool(4));
        RECEIVER.start();
    }

    @DynamicPropertySource
    static void receiver(DynamicPropertyRegistry registry) {
        // Tests drive the sender themselves (no background timer racing them)
        registry.add("swiftdrop.events.push-enabled", () -> "false");
        registry.add("swiftdrop.events.receivers[0].id", () -> "swiftdrop-backend");
        registry.add("swiftdrop.events.receivers[0].audience", () -> "swiftdrop-backend");
        registry.add("swiftdrop.events.receivers[0].push-url",
                () -> "http://localhost:" + RECEIVER.getAddress().getPort() + "/identity-events");
    }

    @AfterAll
    static void stopReceiver() {
        RECEIVER.stop(0);
    }

    @Autowired
    private EventDelivery delivery;

    @Autowired
    private IdentityEvents events;

    @Autowired
    private UserRepository users;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void receiverIsUp() {
        ANSWER.set(202);
        delivery.deliverDue();   // flush anything other tests left behind
        RECEIVED.clear();
    }

    @Test
    void eachNewEventIsPushedOnceAsASignedSet() throws Exception {
        UUID eventId = newEvent();

        delivery.deliverDue();

        Map<String, String> request = requestFor(eventId);
        assertThat(request.get("contentType")).isEqualTo("application/secevent+jwt");
        SignedJWT set = SignedJWT.parse(request.get("body"));
        assertThat(set.getHeader().getType()).hasToString("secevent+jwt");
        assertThat(set.getJWTClaimsSet().getAudience()).containsExactly("swiftdrop-backend");
        assertThat(status(eventId)).isEqualTo("DELIVERED");

        delivery.deliverDue();
        assertThat(RECEIVED.stream().filter(r -> jtiOf(r).equals(eventId.toString()))).hasSize(1);
    }

    @Test
    void aReceiverThatIsDownGetsTheEventLater() {
        UUID eventId = newEvent();
        ANSWER.set(503);

        delivery.deliverDue();

        assertThat(status(eventId)).isEqualTo("PENDING");
        assertThat(attempts(eventId)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT next_attempt_at > now() FROM identity.event_deliveries"
                + " WHERE event_id = ?", Boolean.class, eventId)).as("waits before retrying").isTrue();

        ANSWER.set(202);
        jdbc.update("UPDATE identity.event_deliveries SET next_attempt_at = now() WHERE event_id = ?", eventId);
        delivery.deliverDue();

        assertThat(status(eventId)).isEqualTo("DELIVERED");
    }

    @Test
    void anEventTheReceiverRejectsIsDeadNotRetried() {
        UUID eventId = newEvent();
        ANSWER.set(400);

        delivery.deliverDue();

        assertThat(status(eventId)).as("final: never pushed or polled again").isEqualTo("REJECTED");
        assertThat(jdbc.queryForObject("SELECT last_error FROM identity.event_deliveries WHERE event_id = ?",
                String.class, eventId)).contains("400");
    }

    @Test
    void afterADayOfFailuresTheEventIsGivenUp() {
        UUID eventId = newEvent();
        ANSWER.set(503);
        delivery.deliverDue();
        jdbc.update("UPDATE identity.event_deliveries SET created_at = now() - interval '25 hours',"
                + " next_attempt_at = now() WHERE event_id = ?", eventId);

        delivery.deliverDue();

        assertThat(status(eventId)).isEqualTo("DEAD");
    }

    @Test
    void twoSendersAtTheSameMomentNeverSendTheSameEventTwice() throws Exception {
        List<UUID> ids = List.of(newEvent(), newEvent(), newEvent(), newEvent(), newEvent());
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pods = Executors.newFixedThreadPool(2);
        for (int pod = 0; pod < 2; pod++) {
            pods.submit(() -> {
                start.await();
                delivery.deliverDue();
                return null;
            });
        }
        start.countDown();
        pods.shutdown();
        assertThat(pods.awaitTermination(30, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

        for (UUID id : ids) {
            assertThat(RECEIVED.stream().filter(r -> jtiOf(r).equals(id.toString()))).as("event %s", id).hasSize(1);
        }
    }

    @Test
    void anEventThatCommitsLateIsNeverSkipped() throws Exception {
        UUID slow = newUser();
        UUID fast = newUser();
        CountDownLatch slowRecorded = new CountDownLatch(1);
        CountDownLatch releaseSlow = new CountDownLatch(1);
        ExecutorService writers = Executors.newFixedThreadPool(2);
        // Transaction A records its event (taking the lower number) and then waits before committing
        java.util.concurrent.Future<?> a = writers.submit(() -> transactions.executeWithoutResult(status -> {
            events.purged(slow);
            slowRecorded.countDown();
            awaitQuietly(releaseSlow);
        }));
        assertThat(slowRecorded.await(10, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        // Transaction B records a later event; it must not be able to commit ahead of A
        java.util.concurrent.Future<?> b = writers.submit(() ->
                transactions.executeWithoutResult(status -> events.purged(fast)));
        Thread.sleep(500);
        delivery.deliverDue();   // without ordered commits, the queue's bookmark would jump past A's event here

        releaseSlow.countDown();
        a.get(10, java.util.concurrent.TimeUnit.SECONDS);
        b.get(10, java.util.concurrent.TimeUnit.SECONDS);
        writers.shutdown();
        delivery.deliverDue();

        assertThat(deliveryStatusOfUser(slow)).isEqualTo("DELIVERED");
        assertThat(deliveryStatusOfUser(fast)).isEqualTo("DELIVERED");
    }

    @Test
    void aBrokenEventDoesNotStopTheOthers() {
        // A diary line whose data can't be turned into a SET (payload JSON null)
        UUID broken = jdbc.queryForObject("INSERT INTO identity.identity_events (user_id, user_version, event_type,"
                + " payload, occurred_at) VALUES (gen_random_uuid(), 1,"
                + " 'https://schemas.swiftdrop.me/secevent/identity/profile-updated', 'null'::jsonb, now())"
                + " RETURNING id", UUID.class);
        UUID healthy = newEvent();

        delivery.deliverDue();

        assertThat(status(healthy)).isEqualTo("DELIVERED");
        assertThat(status(broken)).as("retried later, then given up").isEqualTo("PENDING");
        assertThat(attempts(broken)).isEqualTo(1);
    }

    // ---- helpers ----

    private UUID newUser() {
        return transactions.execute(status -> users.saveAndFlush(
                new User(EmailAddress.of("race-" + UUID.randomUUID() + "@example.com"), null)).getId());
    }

    private String deliveryStatusOfUser(UUID userId) {
        return jdbc.queryForObject("SELECT d.status FROM identity.event_deliveries d JOIN identity.identity_events e"
                + " ON e.id = d.event_id WHERE e.user_id = ?", String.class, userId);
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(10, java.util.concurrent.TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private UUID newEvent() {
        return transactions.execute(status -> {
            User user = users.saveAndFlush(new User(EmailAddress.of("signal-" + UUID.randomUUID() + "@example.com"),
                    null));
            events.purged(user.getId());   // the smallest event: no personal data
            return jdbc.queryForObject("SELECT id FROM identity.identity_events WHERE user_id = ?", UUID.class,
                    user.getId());
        });
    }

    private Map<String, String> requestFor(UUID eventId) {
        return RECEIVED.stream().filter(r -> jtiOf(r).equals(eventId.toString())).findFirst().orElseThrow();
    }

    private static String jtiOf(Map<String, String> request) {
        try {
            return SignedJWT.parse(request.get("body")).getJWTClaimsSet().getJWTID();
        } catch (java.text.ParseException notAJwt) {
            return "";
        }
    }

    private String status(UUID eventId) {
        return jdbc.queryForObject("SELECT status FROM identity.event_deliveries WHERE event_id = ?", String.class,
                eventId);
    }

    private int attempts(UUID eventId) {
        return jdbc.queryForObject("SELECT attempts FROM identity.event_deliveries WHERE event_id = ?", Integer.class,
                eventId);
    }
}
