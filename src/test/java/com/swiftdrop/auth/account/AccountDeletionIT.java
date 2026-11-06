package com.swiftdrop.auth.account;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PersonName;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
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
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 3e: "delete my account" starts the erasure (design doc section 7, step 1). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountDeletionIT {

    private static final String ME = "/api/v1/me";
    private static final String PASSWORD = "my parcel arrives on tuesday";

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
    private JdbcTemplate jdbc;

    @Test
    void deletionEndsTheAccountAndKeepsOnlyATombstone() throws Exception {
        String email = uniqueEmail();
        UUID id = namedUser(email);
        String session = refreshTokenFrom(login(email));

        deleteAccount(id, PASSWORD).andExpect(status().isAccepted());

        Map<String, Object> row = jdbc.queryForMap("SELECT email, status, password_hash, name, deleted_at"
                + " FROM identity.users WHERE id = ?", id);
        assertThat(row.get("status")).isEqualTo("DELETED");
        assertThat(row.get("deleted_at")).isNotNull();
        assertThat(row.get("password_hash")).isNull();
        assertThat(row.get("name")).isNull();
        assertThat((String) row.get("email")).isNotEqualTo(email).endsWith(".invalid");
        refresh(session).andExpect(status().isUnauthorized());
        login(email).andExpect(status().isUnauthorized());
    }

    @Test
    void theAddressIsFreeForANewAccountAfterwards() throws Exception {
        String email = uniqueEmail();
        UUID id = namedUser(email);

        deleteAccount(id, PASSWORD).andExpect(status().isAccepted());

        assertThat(users.findByEmail(email)).as("the real address is no longer stored").isEmpty();
        UUID newcomer = namedUser(email);
        assertThat(newcomer).isNotEqualTo(id);
    }

    @Test
    void linkedGoogleLoginsAreRemoved() throws Exception {
        UUID id = namedUser(uniqueEmail());
        jdbc.update("INSERT INTO identity.oauth_accounts (id, user_id, provider, provider_user_id, created_at)"
                + " VALUES (gen_random_uuid(), ?, 'google', ?, now())", id, "google-sub-" + id);

        deleteAccount(id, PASSWORD).andExpect(status().isAccepted());

        // Removed by the google module itself, reacting to the AccountDeleted event (asynchronous, outbox)
        assertThat(waitForZero("SELECT count(*) FROM identity.oauth_accounts WHERE user_id = ?", id)).isZero();
    }

    @Test
    void openEmailChangesAreCancelled() throws Exception {
        String email = uniqueEmail();
        UUID id = namedUser(email);
        jdbc.update("INSERT INTO identity.email_change_requests (user_id, old_email, new_email, confirm_expires_at)"
                + " VALUES (?, ?, ?, now() + interval '1 hour')", id, email, "next-" + email);

        deleteAccount(id, PASSWORD).andExpect(status().isAccepted());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.email_change_requests"
                + " WHERE user_id = ? AND cancelled_at IS NULL", Integer.class, id)).isZero();
    }

    @Test
    void anOldUndoLinkCannotBringTheAddressBack() throws Exception {
        String email = uniqueEmail();
        UUID id = namedUser(email);
        jdbc.update("INSERT INTO identity.email_change_requests (user_id, old_email, new_email, confirm_expires_at,"
                + " confirmed_at, revert_token_hash, revert_expires_at) VALUES (?, ?, ?, now() + interval '1 hour',"
                + " now(), ?, now() + interval '1 day')", id, email, "next-" + email, "a".repeat(64));

        deleteAccount(id, PASSWORD).andExpect(status().isAccepted());

        // The whole history (old/new addresses and undo-link hashes) is erased with the account
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.email_change_requests WHERE user_id = ?",
                Integer.class, id)).isZero();
    }

    @Test
    void theTombstoneKeepsNoRolesAndCannotExportOrDeleteAgain() throws Exception {
        UUID id = namedUser(uniqueEmail());
        jdbc.update("INSERT INTO identity.user_roles (user_id, role_id)"
                + " SELECT ?, id FROM identity.roles WHERE name = 'CUSTOMER'", id);

        deleteAccount(id, PASSWORD).andExpect(status().isAccepted());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.user_roles WHERE user_id = ?", Integer.class, id))
                .isZero();
        String access = issuer.issue(id, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/me/export")
                .header("Authorization", "Bearer " + access)).andExpect(status().isUnauthorized());
        deleteAccount(id, PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void aWrongPasswordDeletesNothing() throws Exception {
        String email = uniqueEmail();
        UUID id = namedUser(email);

        deleteAccount(id, "not the right password at all").andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTHENTICATION_FAILED"));

        login(email).andExpect(status().isOk());
    }

    @Test
    void aMerchantMachineTokenCannotDeleteAnything() throws Exception {
        String machine = "Bearer " + issuer.issueForClient("swiftdrop-web", UUID.randomUUID(), List.of("MERCHANT"),
                List.of("parcel:create")).value();

        mockMvc.perform(delete(ME).header("Authorization", machine).contentType(MediaType.APPLICATION_JSON)
                .content(body(PASSWORD))).andExpect(status().isForbidden());
    }

    // ---- helpers ----

    private ResultActions deleteAccount(UUID userId, String password) throws Exception {
        String access = issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        return mockMvc.perform(delete(ME).header("Authorization", "Bearer " + access)
                .contentType(MediaType.APPLICATION_JSON).content(body(password)));
    }

    private static String body(String password) {
        return "{\"current_password\":\"" + password + "\"}";
    }

    private ResultActions login(String email) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"));
    }

    private static String refreshTokenFrom(ResultActions login) throws Exception {
        return JsonPath.read(login.andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
                "$.refresh_token");
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content("{\"refresh_token\":\"" + refreshToken + "\"}"));
    }

    // Async work: poll up to 10 s instead of sleeping a fixed time
    private int waitForZero(String sql, UUID id) throws InterruptedException {
        int count = -1;
        for (int attempt = 0; attempt < 100 && count != 0; attempt++) {
            count = jdbc.queryForObject(sql, Integer.class, id);
            if (count != 0) {
                Thread.sleep(100);
            }
        }
        return count;
    }

    private UUID namedUser(String email) {
        String hash = encoder.encode(PASSWORD);
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), hash);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), Instant.now());
            return users.saveAndFlush(user).getId();
        });
    }

    private static String uniqueEmail() {
        return "delete-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
