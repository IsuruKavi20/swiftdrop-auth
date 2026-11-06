package com.swiftdrop.auth.user;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 6a: every change to a person is recorded as an event, in the SAME transaction as the change. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdentityEventsIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final String RISC = "https://schemas.openid.net/secevent/risc/event-type/";
    private static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
    private static final String OURS = "https://schemas.swiftdrop.me/secevent/identity/";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private IdentityEvents events;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private com.swiftdrop.auth.admin.RoleAdministration roleAdministration;

    @Autowired
    private com.swiftdrop.auth.google.GoogleAccountLinker googleLinker;

    @Autowired
    private com.swiftdrop.auth.session.SessionService sessions;

    @Autowired
    private IdentityEventRetention retention;

    @Test
    void eachEventGetsTheNextVersionOfThatPerson() {
        UUID id = person();

        transactions.executeWithoutResult(status -> {
            User user = users.findById(id).orElseThrow();
            events.profileUpdated(user);
            events.profileUpdated(user);
        });

        assertThat(versions(id)).containsExactly(1L, 2L);
    }

    @Test
    void noChangeNoEvent_aRolledBackChangeLeavesNoEvent() {
        UUID id = person();

        transactions.executeWithoutResult(status -> {
            events.profileUpdated(users.findById(id).orElseThrow());
            status.setRollbackOnly();   // the change "failed": its event must vanish with it
        });

        assertThat(versions(id)).isEmpty();
    }

    @Test
    void recordingOutsideATransactionIsRefused() {
        User user = users.findById(person()).orElseThrow();

        assertThatThrownBy(() -> events.profileUpdated(user)).isInstanceOf(IllegalTransactionStateException.class);
    }

    @Test
    void editingTheProfileRecordsProfileUpdatedWithTheNewName() throws Exception {
        UUID id = person();
        String etag = mockMvc.perform(get("/api/v1/me/profile").header("Authorization", bearer(id)))
                .andReturn().getResponse().getHeader("ETag");

        mockMvc.perform(patch("/api/v1/me/profile").header("Authorization", bearer(id)).header("If-Match", etag)
                        .contentType("application/merge-patch+json").content("{\"name\":\"Nimal K. Perera\"}"))
                .andExpect(status().isOk());

        Map<String, Object> event = lastEvent(id);
        assertThat(event.get("event_type")).isEqualTo(OURS + "profile-updated");
        assertThat(event.get("payload").toString()).contains("Nimal K. Perera");
    }

    @Test
    void deletingTheAccountRecordsSessionsEndedThenPurged() throws Exception {
        UUID id = person();

        mockMvc.perform(delete("/api/v1/me").header("Authorization", bearer(id))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"current_password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isAccepted());

        // No session existed, so no "sessions ended" event: only real changes are recorded
        assertThat(types(id)).containsExactly(RISC + "account-purged");
        // The purge event carries no personal data at all
        assertThat(lastEvent(id).get("payload").toString()).doesNotContain("@", "Nimal");
    }

    @Test
    void deletingTheAccountWipesThePersonalDataOfItsEarlierEvents() throws Exception {
        UUID id = person();
        transactions.executeWithoutResult(status -> events.registered(users.findWithRolesById(id).orElseThrow()));

        mockMvc.perform(delete("/api/v1/me").header("Authorization", bearer(id))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"current_password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isAccepted());

        assertThat(jdbc.queryForList("SELECT payload::text FROM identity.identity_events WHERE user_id = ?",
                String.class, id)).allMatch(payload -> payload.equals("{}"));
    }

    @Test
    void grantingARoleRecordsTheNewRoleList() {
        UUID id = person();

        roleAdministration.grant(UUID.randomUUID(), id, RoleName.COURIER);

        assertThat(types(id)).containsExactly(OURS + "roles-changed");
        assertThat(lastEvent(id).get("payload").toString()).contains("COURIER");
    }

    @Test
    void aNewGoogleAccountIsRegistered() {
        UUID id = googleLinker.link(new com.swiftdrop.auth.google.GoogleIdentity(String.valueOf(System.nanoTime()),
                "events-g-" + UUID.randomUUID().toString().substring(0, 8) + "@gmail.com", true, null));

        assertThat(types(id)).containsExactly(OURS + "user-registered");
    }

    @Test
    void changingThePasswordRecordsACredentialChange() throws Exception {
        UUID id = person();

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/me/password")
                        .header("Authorization", bearer(id)).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"current_password\":\"" + PASSWORD
                                + "\",\"new_password\":\"a brand new and much longer passphrase\"}"))
                .andExpect(status().isOk());

        assertThat(types(id)).first().isEqualTo(CAEP + "credential-change");
    }

    @Test
    void endingSessionsThatDontExistRecordsNothing() {
        UUID id = person();

        transactions.executeWithoutResult(status ->
                sessions.endAllSessions(id, com.swiftdrop.auth.session.RevokeReason.LOGOUT));

        assertThat(types(id)).isEmpty();
    }

    @Test
    void oldEventsAreDeletedAfterTheRetentionPeriod() {
        UUID oldEvent = jdbc.queryForObject("INSERT INTO identity.identity_events (user_id, user_version, event_type,"
                + " payload, occurred_at) VALUES (gen_random_uuid(), 1, 'https://schemas.swiftdrop.me/secevent/"
                + "identity/profile-updated', '{}'::jsonb, now() - interval '40 days') RETURNING id", UUID.class);
        UUID recent = person();
        transactions.executeWithoutResult(status -> events.profileUpdated(users.findById(recent).orElseThrow()));

        retention.deleteExpired();

        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.identity_events WHERE id = ?", Integer.class,
                oldEvent)).isZero();
        assertThat(versions(recent)).containsExactly(1L);
    }

    @Test
    void eventsNeverContainSecrets() {
        UUID id = person();

        transactions.executeWithoutResult(status -> events.registered(users.findWithRolesById(id).orElseThrow()));

        assertThat(lastEvent(id).get("payload").toString()).doesNotContain("argon2", "password", "hash");
    }

    // ---- helpers ----

    private List<Long> versions(UUID id) {
        return jdbc.queryForList("SELECT user_version FROM identity.identity_events WHERE user_id = ? ORDER BY seq",
                Long.class, id);
    }

    private List<String> types(UUID id) {
        return jdbc.queryForList("SELECT event_type FROM identity.identity_events WHERE user_id = ? ORDER BY seq",
                String.class, id);
    }

    private Map<String, Object> lastEvent(UUID id) {
        return jdbc.queryForMap("SELECT event_type, payload::text AS payload FROM identity.identity_events"
                + " WHERE user_id = ? ORDER BY seq DESC LIMIT 1", id);
    }

    private String bearer(UUID userId) {
        return "Bearer " + issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
    }

    private UUID person() {
        String hash = encoder.encode(PASSWORD);
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("events-" + UUID.randomUUID() + "@example.com"), hash);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), Instant.now());
            return users.saveAndFlush(user).getId();
        });
    }
}
