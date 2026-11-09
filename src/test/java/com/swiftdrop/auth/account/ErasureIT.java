package com.swiftdrop.auth.account;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.user.EmailAddress;
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
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Identity step 8: erasure everywhere. A deleted person (tombstone) is hard-deleted once every receiver confirmed it
 * erased its copy, or after 30 days at the latest; only an id-and-dates line stays in the erasure log.
 */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ErasureIT {

    private static final String RECEIVER_SECRET = "events-poller-test-secret-0123456789abcdef";
    private static final String OTHER_SECRET = "erasure-other-test-secret-0123456789abcdef";

    // Same receiver as EventPollIT (so the test context is shared): "swiftdrop-backend", poll-only
    @DynamicPropertySource
    static void receiver(DynamicPropertyRegistry registry) {
        registry.add("swiftdrop.events.receivers[0].id", () -> "swiftdrop-backend");
        registry.add("swiftdrop.events.receivers[0].audience", () -> "swiftdrop-backend");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ErasureCompletion completion;

    private String receiverToken;

    @BeforeEach
    void serviceToken() throws Exception {
        receiverToken = serviceToken("svc_swiftdrop-backend", RECEIVER_SECRET);
    }

    @Test
    void hardDeleteWaitsForAllReceivers() throws Exception {
        UUID gone = deletedPerson();

        completion.completeDue();
        assertThat(users.existsById(gone)).as("SwiftDrop hasn't confirmed yet").isTrue();

        confirm(receiverToken, gone).andExpect(status().isNoContent());
        completion.completeDue();

        assertThat(users.existsById(gone)).isFalse();
        assertThat(logOf(gone)).containsEntry("complete", true);
    }

    @Test
    void hardDeleteAfter30DaysEvenWithoutConfirmation() {
        UUID gone = deletedPerson();
        jdbc.update("UPDATE identity.users SET deleted_at = ? WHERE id = ?",
                Timestamp.from(Instant.now().minus(31, ChronoUnit.DAYS)), gone);

        completion.completeDue();

        assertThat(users.existsById(gone)).isFalse();
        assertThat(logOf(gone)).containsEntry("complete", false);
    }

    @Test
    void confirmTwiceIsFine() throws Exception {
        UUID gone = deletedPerson();

        confirm(receiverToken, gone).andExpect(status().isNoContent());
        confirm(receiverToken, gone).andExpect(status().isNoContent());
        completion.completeDue();
        // Even after the hard delete, a late repeat is still fine (the receiver may retry)
        confirm(receiverToken, gone).andExpect(status().isNoContent());
    }

    @Test
    void unknownIdIs404() throws Exception {
        confirm(receiverToken, UUID.randomUUID()).andExpect(status().isNotFound());
        // A living person can't be "confirmed erased"
        confirm(receiverToken, activePerson()).andExpect(status().isNotFound());
    }

    @Test
    void confirmIsOnlyForItsOwnReceiver() throws Exception {
        UUID gone = deletedPerson();

        confirm(serviceToken("svc_other-app", OTHER_SECRET), gone).andExpect(status().isForbidden());
        confirm("Bearer not-a-token", gone).andExpect(status().isUnauthorized());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.erasure_confirmations WHERE user_id = ?",
                Integer.class, gone)).isZero();
    }

    @Test
    void hardDeleteRemovesEveryLinkedRow() throws Exception {
        UUID gone = deletedPerson();
        jdbc.update("INSERT INTO identity.role_applications (id, user_id, role, status, created_at)"
                + " VALUES (?, ?, 'COURIER', 'PENDING', now())", UUID.randomUUID(), gone);
        confirm(receiverToken, gone).andExpect(status().isNoContent());

        completion.completeDue();

        for (String table : List.of("role_applications", "refresh_tokens", "oauth_accounts", "user_roles",
                "erasure_confirmations")) {
            assertThat(jdbc.queryForObject("SELECT count(*) FROM identity." + table + " WHERE user_id = ?",
                    Integer.class, gone)).as(table).isZero();
        }
    }

    @Test
    void approverDecisionsSurviveAsBareIds() throws Exception {
        UUID approver = deletedPerson();
        UUID applicant = activePerson();
        UUID decision = UUID.randomUUID();
        jdbc.update("INSERT INTO identity.role_applications (id, user_id, role, status, created_at, decided_by,"
                + " decided_at) VALUES (?, ?, 'COURIER', 'APPROVED', now(), ?, now())", decision, applicant, approver);
        confirm(receiverToken, approver).andExpect(status().isNoContent());

        completion.completeDue();

        assertThat(users.existsById(approver)).isFalse();
        assertThat(jdbc.queryForObject("SELECT decided_by FROM identity.role_applications WHERE id = ?",
                UUID.class, decision)).as("who approved stays known, as an id only").isEqualTo(approver);
    }

    @Test
    void erasureLogHoldsNoPersonalData() {
        List<String> columns = jdbc.queryForList("SELECT column_name FROM information_schema.columns"
                + " WHERE table_schema = 'identity' AND table_name = 'erasure_log' ORDER BY column_name", String.class);

        assertThat(columns).containsExactly("complete", "deleted_at", "erased_at", "user_id");
    }

    @Test
    void twoPodsNeverHardDeleteTwice() throws Exception {
        UUID gone = deletedPerson();
        confirm(receiverToken, gone).andExpect(status().isNoContent());

        ExecutorService pods = Executors.newFixedThreadPool(2);
        try {
            Callable<Integer> run = completion::completeDue;
            List<Integer> erased = pods.invokeAll(List.of(run, run)).stream().map(future -> {
                try {
                    return future.get();
                } catch (Exception failed) {
                    throw new IllegalStateException(failed);
                }
            }).toList();
            // Each run may also finish other tests' leftovers; this person is erased exactly once, without errors
            assertThat(erased).allMatch(count -> count >= 0);
        } finally {
            pods.shutdown();
        }
        assertThat(users.existsById(gone)).isFalse();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.erasure_log WHERE user_id = ?",
                Integer.class, gone)).isOne();
    }

    // ---- helpers ----

    private ResultActions confirm(String bearer, UUID userId) throws Exception {
        return mockMvc.perform(post("/api/v1/directory/erasure/" + userId + "/confirm")
                .header("Authorization", bearer));
    }

    private Map<String, Object> logOf(UUID userId) {
        return jdbc.queryForMap("SELECT complete FROM identity.erasure_log WHERE user_id = ?", userId);
    }

    private UUID deletedPerson() {
        return transactions.execute(status -> {
            User user = users.saveAndFlush(new User(EmailAddress.of(uniqueEmail()), null));
            user.beginDeletion(Instant.now());
            return users.saveAndFlush(user).getId();
        });
    }

    private UUID activePerson() {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(uniqueEmail()), null);
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });
    }

    private String serviceToken(String clientId, String secret) throws Exception {
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        String body = mockMvc.perform(post("/oauth2/token").header("Authorization", "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=client_credentials"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(body, "$.access_token");
    }

    private static String uniqueEmail() {
        return "erase-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
