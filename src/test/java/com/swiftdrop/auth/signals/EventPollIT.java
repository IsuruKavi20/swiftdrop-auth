package com.swiftdrop.auth.signals;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jwt.SignedJWT;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 6d: a receiver collects (and confirms) its events by polling (RFC 8936). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EventPollIT {

    private static final String POLL = "/api/v1/events/poll";
    // Configured in application-test.yml with events:read (only the SHA-256 of this secret is stored there)
    private static final String POLLER = "svc_swiftdrop-backend";
    private static final String POLLER_SECRET = "events-poller-test-secret-0123456789abcdef";

    @DynamicPropertySource
    static void receiver(DynamicPropertyRegistry registry) {
        // A poll-only receiver: no push-url (it can't be reached, e.g. it runs on a laptop). Push stays switched on,
        // and must simply skip it.
        registry.add("swiftdrop.events.receivers[0].id", () -> "swiftdrop-backend");
        registry.add("swiftdrop.events.receivers[0].audience", () -> "swiftdrop-backend");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IdentityEvents events;

    @Autowired
    private UserRepository users;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private EventDelivery delivery;

    @BeforeEach
    void confirmEverythingLeftByOtherTests() throws Exception {
        drain();
    }

    @Test
    void returnsMyPendingEventsAsSignedSets() throws Exception {
        UUID eventId = newEvent();

        Map<String, String> sets = poll("{}");

        assertThat(sets).containsKey(eventId.toString());
        SignedJWT set = SignedJWT.parse(sets.get(eventId.toString()));
        assertThat(set.getHeader().getType()).hasToString("secevent+jwt");
        assertThat(set.getJWTClaimsSet().getAudience()).containsExactly("swiftdrop-backend");
    }

    @Test
    void aPollOnlyReceiverIsNeverPushedTo() throws Exception {
        UUID event = newEvent();

        delivery.deliverDue();

        // No push was tried (a failed try counts an attempt); the event waits for the receiver's poll
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM identity.event_deliveries WHERE event_id = ?"
                + " AND attempts > 0", Integer.class, event)).isZero();
        assertThat(poll("{\"maxEvents\":10}")).containsKey(event.toString());
    }

    @Test
    void anAcknowledgedEventIsDeliveredAndNotReturnedAgain() throws Exception {
        UUID eventId = newEvent();
        poll("{}");

        poll("{\"ack\":[\"" + eventId + "\"]}");

        assertThat(deliveryStatus(eventId)).isEqualTo("DELIVERED");
        assertThat(poll("{}")).doesNotContainKey(eventId.toString());
    }

    @Test
    void anEventTheReceiverReportsAsWrongIsRejectedForGood() throws Exception {
        UUID eventId = newEvent();

        poll("{\"setErrs\":{\"" + eventId + "\":{\"err\":\"invalid_request\",\"description\":\"bad\"}}}");

        assertThat(deliveryStatus(eventId)).isEqualTo("REJECTED");
        assertThat(poll("{}")).doesNotContainKey(eventId.toString());
    }

    @Test
    void anEventWhosePushWasGivenUpCanStillBeCollected() throws Exception {
        UUID eventId = newEvent();
        poll("{\"maxEvents\":0}");   // makes sure it is queued
        jdbc.update("UPDATE identity.event_deliveries SET status = 'DEAD' WHERE event_id = ?", eventId);

        assertThat(poll("{}")).containsKey(eventId.toString());
    }

    @Test
    void returnsAtMostMaxEventsAndSaysWhenMoreAreWaiting() throws Exception {
        newEvent();
        newEvent();
        newEvent();

        String body = pollRaw("{\"maxEvents\":2}").andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString();

        assertThat((Map<?, ?>) JsonPath.read(body, "$.sets")).hasSize(2);
        assertThat((Boolean) JsonPath.read(body, "$.moreAvailable")).isTrue();
    }

    @Test
    void onlyTheReceiversOwnClientMayPoll() throws Exception {
        String directoryReader = serviceToken("svc_swiftdrop-reader", "directory-reader-test-secret-0123456789abcdef");
        String user = "Bearer " + issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("ADMIN"),
                List.of("user:read")).value();

        mockMvc.perform(post(POLL).header("Authorization", directoryReader).contentType(MediaType.APPLICATION_JSON)
                .content("{}")).andExpect(status().isForbidden());
        mockMvc.perform(post(POLL).header("Authorization", user).contentType(MediaType.APPLICATION_JSON)
                .content("{}")).andExpect(status().isForbidden());
        mockMvc.perform(post(POLL).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void aMalformedEventIdIsTheCallersMistake() throws Exception {
        pollRaw("{\"setErrs\":{\"not-a-uuid\":{\"err\":\"invalid_request\"}}}").andExpect(status().isBadRequest());
    }

    @Test
    void maxEventsIsLimited() throws Exception {
        pollRaw("{\"maxEvents\":101}").andExpect(status().isBadRequest());
    }

    // ---- helpers ----

    private Map<String, String> poll(String body) throws Exception {
        String response = pollRaw(body).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return JsonPath.read(response, "$.sets");
    }

    private ResultActions pollRaw(String body) throws Exception {
        return mockMvc.perform(post(POLL).header("Authorization", serviceToken(POLLER, POLLER_SECRET))
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private void drain() throws Exception {
        Map<String, String> waiting = poll("{\"maxEvents\":100}");
        while (!waiting.isEmpty()) {
            waiting = poll("{\"maxEvents\":100,\"ack\":[\"" + String.join("\",\"", waiting.keySet()) + "\"]}");
        }
    }

    private UUID newEvent() {
        return transactions.execute(status -> {
            User user = users.saveAndFlush(new User(EmailAddress.of("poll-" + UUID.randomUUID() + "@example.com"),
                    null));
            events.purged(user.getId());
            return jdbc.queryForObject("SELECT id FROM identity.identity_events WHERE user_id = ?", UUID.class,
                    user.getId());
        });
    }

    private String deliveryStatus(UUID eventId) {
        return jdbc.queryForObject("SELECT status FROM identity.event_deliveries WHERE event_id = ?", String.class,
                eventId);
    }

    private String serviceToken(String clientId, String secret) throws Exception {
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        String body = mockMvc.perform(post("/oauth2/token").header("Authorization", "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=client_credentials"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(body, "$.access_token");
    }
}
