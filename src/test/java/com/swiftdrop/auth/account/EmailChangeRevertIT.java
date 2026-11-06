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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 3b-3: the undo link from the OLD inbox restores the address and logs everyone out. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EmailChangeRevertIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final String REVERT = "/api/v1/auth/email-change/revert";
    private static final Pattern CONFIRM_TOKEN = Pattern.compile("/confirm-email-change#token=([A-Za-z0-9_-]{43})");
    private static final Pattern UNDO_TOKEN = Pattern.compile("/revert-email-change#token=([A-Za-z0-9_-]{43})");

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
    void undoRestoresTheOldAddressAndLogsEveryoneOut() throws Exception {
        String oldEmail = uniqueEmail();
        String attackerEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String undo = changeConfirmed(id, oldEmail, attackerEmail);
        String attackerSession = loginRefreshToken(attackerEmail);

        revert(undo).andExpect(status().isNoContent());

        User user = users.findById(id).orElseThrow();
        assertThat(user.getEmail()).isEqualTo(oldEmail);
        assertThat(user.isEmailVerified()).isTrue();
        mockMvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refresh_token\":\"" + attackerSession + "\"}"))
                .andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.refresh_tokens"
                + " WHERE user_id = ? AND revoke_reason = 'EMAIL_CHANGE_UNDONE'", Integer.class, id)).isPositive();
    }

    @Test
    void undoStillWinsAfterTheAttackerChangedTheEmailAgain() throws Exception {
        String oldEmail = uniqueEmail();
        String firstAttackerEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String undo = changeConfirmed(id, oldEmail, firstAttackerEmail);
        jdbc.update("UPDATE identity.email_change_requests SET created_at = created_at - interval '2 minutes'"
                + " WHERE user_id = ?", id);   // past the cooldown
        changeConfirmed(id, firstAttackerEmail, uniqueEmail());

        revert(undo).andExpect(status().isNoContent());

        assertThat(users.findById(id).orElseThrow().getEmail()).isEqualTo(oldEmail);
    }

    @Test
    void undoAlsoCancelsAnOpenChangeRequest() throws Exception {
        String oldEmail = uniqueEmail();
        String attackerEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String undo = changeConfirmed(id, oldEmail, attackerEmail);
        jdbc.update("UPDATE identity.email_change_requests SET created_at = created_at - interval '2 minutes'"
                + " WHERE user_id = ?", id);
        String pendingConfirm = requestChange(id, uniqueEmail());   // the attacker's next attempt, not yet confirmed

        revert(undo).andExpect(status().isNoContent());

        confirm(pendingConfirm).andExpect(status().isBadRequest());
        assertThat(users.findById(id).orElseThrow().getEmail()).isEqualTo(oldEmail);
    }

    @Test
    void anUndoLinkLastsThreeDays() throws Exception {
        String oldEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        changeConfirmed(id, oldEmail, uniqueEmail());

        Integer hours = jdbc.queryForObject("SELECT CAST(EXTRACT(EPOCH FROM (revert_expires_at - confirmed_at)) / 3600"
                + " AS INTEGER) FROM identity.email_change_requests WHERE user_id = ?", Integer.class, id);
        assertThat(hours).isEqualTo(72);
    }

    @Test
    void theUndoLinkWorksOnlyOnce() throws Exception {
        String oldEmail = uniqueEmail();
        String undo = changeConfirmed(userWithPassword(oldEmail), oldEmail, uniqueEmail());

        revert(undo).andExpect(status().isNoContent());
        revert(undo).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EMAIL_CHANGE_LINK"));
    }

    @Test
    void anExpiredUndoLinkDoesNothing() throws Exception {
        String oldEmail = uniqueEmail();
        String newEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String undo = changeConfirmed(id, oldEmail, newEmail);
        jdbc.update("UPDATE identity.email_change_requests SET revert_expires_at = now() - interval '1 minute'"
                + " WHERE user_id = ?", id);

        revert(undo).andExpect(status().isBadRequest());

        assertThat(users.findById(id).orElseThrow().getEmail()).isEqualTo(newEmail);
    }

    @Test
    void aConfirmLinkCannotBeUsedAsAnUndoLink() throws Exception {
        String oldEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String confirmToken = requestChange(id, uniqueEmail());

        revert(confirmToken).andExpect(status().isBadRequest());
        revert("not-a-token").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EMAIL_CHANGE_LINK"));
    }

    // ---- helpers ----

    /** Request + confirm through the API; returns the undo token emailed to the old address. */
    private String changeConfirmed(UUID userId, String currentEmail, String newEmail) throws Exception {
        confirm(requestChange(userId, newEmail)).andExpect(status().isNoContent());
        return tokenIn(mailpit.awaitMessageTo(currentEmail, SmtpAccountEmailSubjects.EMAIL_CHANGED), UNDO_TOKEN);
    }

    private String requestChange(UUID userId, String newEmail) throws Exception {
        String access = issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        mockMvc.perform(post("/api/v1/me/email-change").header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"new_email\":\"" + newEmail + "\",\"current_password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isAccepted());
        return tokenIn(mailpit.awaitMessageTo(newEmail, SmtpAccountEmailSubjects.CONFIRM_NEW_EMAIL), CONFIRM_TOKEN);
    }

    private ResultActions confirm(String token) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/email-change/confirm").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}"));
    }

    private ResultActions revert(String token) throws Exception {
        return mockMvc.perform(post(REVERT).contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}"));
    }

    private String loginRefreshToken(String email) throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.refresh_token");
    }

    private static String tokenIn(MailpitClient.Mail mail, Pattern pattern) {
        Matcher token = pattern.matcher(mail.text());
        assertThat(token.find()).isTrue();
        return token.group(1);
    }

    private UUID userWithPassword(String email) {
        String hash = encoder.encode(PASSWORD);
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), hash);
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });
    }

    private static String uniqueEmail() {
        return "undo-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
