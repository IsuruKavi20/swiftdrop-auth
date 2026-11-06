package com.swiftdrop.auth.account;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.MailpitClient;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
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

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 3c: change my password (current password required, every old session ends, this device continues). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PasswordChangeIT {

    private static final String CHANGE = "/api/v1/me/password";
    private static final String OLD_PASSWORD = "my parcel arrives on tuesday";
    private static final String NEW_PASSWORD = "a brand new and much longer passphrase";

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

    @Autowired
    private MailpitClient mailpit;

    @Test
    void theNewPasswordWorksTheOldOneNoLongerDoes() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email);

        change(id, OLD_PASSWORD, NEW_PASSWORD).andExpect(status().isOk());

        login(email, NEW_PASSWORD).andExpect(status().isOk());
        login(email, OLD_PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void everyOldSessionEndsAndThisDeviceGetsFreshTokens() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email);
        String laptopSession = refreshTokenFrom(login(email, OLD_PASSWORD));

        String body = change(id, OLD_PASSWORD, NEW_PASSWORD).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.access_token").exists())
                .andReturn().getResponse().getContentAsString();
        String freshSession = JsonPath.read(body, "$.refresh_token");

        refresh(laptopSession).andExpect(status().isUnauthorized());
        refresh(freshSession).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.refresh_tokens"
                + " WHERE user_id = ? AND revoke_reason = 'PASSWORD_CHANGED'", Integer.class, id)).isPositive();
    }

    @Test
    void theOwnerIsToldByEmail() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email);

        change(id, OLD_PASSWORD, NEW_PASSWORD).andExpect(status().isOk());

        MailpitClient.Mail notice = mailpit.awaitMessageTo(email, SmtpAccountEmailSubjects.PASSWORD_CHANGED);
        assertThat(notice.text()).doesNotContain(NEW_PASSWORD);
    }

    @Test
    void aWrongCurrentPasswordChangesNothing() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email);

        change(id, "not the right password at all", NEW_PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTHENTICATION_FAILED"));

        login(email, OLD_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void theNewPasswordMustFollowTheSameRulesAsSignup() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email);

        change(id, OLD_PASSWORD, "short").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("WEAK_PASSWORD"));

        login(email, OLD_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void anAccountWithoutAPasswordCannotChangeOneYet() throws Exception {
        UUID googleOnly = transactions.execute(status -> {
            User user = new User(EmailAddress.of(uniqueEmail()), null);
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });

        change(googleOnly, "anything", NEW_PASSWORD).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTHENTICATION_REQUIRED"));
    }

    @Test
    void aMerchantMachineTokenHasNoPassword() throws Exception {
        String machine = "Bearer " + issuer.issueForClient("swiftdrop-web", UUID.randomUUID(), List.of("MERCHANT"),
                List.of("parcel:create")).value();

        mockMvc.perform(post(CHANGE).header("Authorization", machine).contentType(MediaType.APPLICATION_JSON)
                        .content(body(OLD_PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isForbidden());
    }

    // ---- helpers ----

    private ResultActions change(UUID userId, String current, String next) throws Exception {
        String access = issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        return mockMvc.perform(post(CHANGE).header("Authorization", "Bearer " + access)
                .contentType(MediaType.APPLICATION_JSON).content(body(current, next)));
    }

    private static String body(String current, String next) {
        return "{\"current_password\":\"" + current + "\",\"new_password\":\"" + next + "\"}";
    }

    private ResultActions login(String email, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"));
    }

    private static String refreshTokenFrom(ResultActions login) throws Exception {
        return JsonPath.read(login.andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
                "$.refresh_token");
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content("{\"refresh_token\":\"" + refreshToken + "\"}"));
    }

    private UUID userWithPassword(String email) {
        String hash = encoder.encode(OLD_PASSWORD);
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), hash);
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });
    }

    private static String uniqueEmail() {
        return "pw-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
