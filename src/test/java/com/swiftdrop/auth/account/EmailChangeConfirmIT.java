package com.swiftdrop.auth.account;

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

/** Identity step 3b-2: the link from the NEW inbox switches the login email; the OLD inbox gets an undo link. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EmailChangeConfirmIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final String CONFIRM = "/api/v1/auth/email-change/confirm";
    private static final Pattern CONFIRM_TOKEN = Pattern.compile("/confirm-email-change#token=([A-Za-z0-9_-]{43})");

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
    void theLinkSwitchesTheEmailAndTheOldAddressGetsAnUndoLink() throws Exception {
        String oldEmail = uniqueEmail();
        String newEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);

        confirm(linkSentTo(id, newEmail)).andExpect(status().isNoContent());

        User user = users.findById(id).orElseThrow();
        assertThat(user.getEmail()).isEqualTo(newEmail);
        assertThat(user.isEmailVerified()).isTrue();
        MailpitClient.Mail changed = mailpit.awaitMessageTo(oldEmail, SmtpAccountEmailSubjects.EMAIL_CHANGED);
        assertThat(changed.text()).containsPattern("/revert-email-change#token=[A-Za-z0-9_-]{43}");
        assertThat(jdbc.queryForObject("SELECT revert_token_hash FROM identity.email_change_requests"
                + " WHERE user_id = ?", String.class, id)).matches("^[0-9a-f]{64}$");
    }

    @Test
    void afterTheChangeTheUserLogsInWithTheNewEmail() throws Exception {
        String newEmail = uniqueEmail();
        UUID id = userWithPassword(uniqueEmail());

        confirm(linkSentTo(id, newEmail)).andExpect(status().isNoContent());

        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + newEmail + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists());
    }

    @Test
    void theLinkWorksOnlyOnce() throws Exception {
        String token = linkSentTo(userWithPassword(uniqueEmail()), uniqueEmail());

        confirm(token).andExpect(status().isNoContent());
        confirm(token).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EMAIL_CHANGE_LINK"));
    }

    @Test
    void anExpiredLinkDoesNothing() throws Exception {
        String oldEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String token = linkSentTo(id, uniqueEmail());
        jdbc.update("UPDATE identity.email_change_requests SET confirm_expires_at = now() - interval '1 minute'"
                + " WHERE user_id = ?", id);

        confirm(token).andExpect(status().isBadRequest());

        assertThat(users.findById(id).orElseThrow().getEmail()).isEqualTo(oldEmail);
    }

    @Test
    void aLinkReplacedByANewerRequestDoesNothing() throws Exception {
        String oldEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String first = linkSentTo(id, uniqueEmail());
        jdbc.update("UPDATE identity.email_change_requests SET created_at = created_at - interval '2 minutes'"
                + " WHERE user_id = ?", id);   // past the cooldown
        linkSentTo(id, uniqueEmail());

        confirm(first).andExpect(status().isBadRequest());

        assertThat(users.findById(id).orElseThrow().getEmail()).isEqualTo(oldEmail);
    }

    @Test
    void anAddressTakenMeanwhileIsNeverDoubleUsed() throws Exception {
        String oldEmail = uniqueEmail();
        String contested = uniqueEmail();
        UUID id = userWithPassword(oldEmail);
        String token = linkSentTo(id, contested);
        userWithPassword(contested);   // someone else registered it after the link was sent

        confirm(token).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EMAIL_CHANGE_LINK"));

        assertThat(users.findById(id).orElseThrow().getEmail()).isEqualTo(oldEmail);
    }

    @Test
    void garbageAndUnknownLinksGetTheSameAnswer() throws Exception {
        confirm("not-a-token").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EMAIL_CHANGE_LINK"));
        confirm("A".repeat(43)).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EMAIL_CHANGE_LINK"));
    }

    // ---- helpers ----

    /** Requests a change through the API and returns the token from the confirmation email. */
    private String linkSentTo(UUID userId, String newEmail) throws Exception {
        String access = issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        mockMvc.perform(post("/api/v1/me/email-change").header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"new_email\":\"" + newEmail + "\",\"current_password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isAccepted());
        Matcher token = CONFIRM_TOKEN.matcher(
                mailpit.awaitMessageTo(newEmail, SmtpAccountEmailSubjects.CONFIRM_NEW_EMAIL).text());
        assertThat(token.find()).isTrue();
        return token.group(1);
    }

    private ResultActions confirm(String token) throws Exception {
        return mockMvc.perform(post(CONFIRM).contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}"));
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
        return "confirm-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
