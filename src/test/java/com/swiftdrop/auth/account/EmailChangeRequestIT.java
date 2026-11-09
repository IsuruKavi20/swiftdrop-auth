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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 3b-1: asking to change the login email (re-authentication, emails to the new and old address). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EmailChangeRequestIT {

    private static final String CHANGE = "/api/v1/me/email-change";
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

    @Autowired
    private MailpitClient mailpit;

    @Test
    void sendsAConfirmationLinkToTheNewAddressAndANoticeToTheOldOne() throws Exception {
        String oldEmail = uniqueEmail();
        String newEmail = uniqueEmail();
        UUID id = userWithPassword(oldEmail);

        requestChange(id, newEmail, PASSWORD).andExpect(status().isAccepted());

        MailpitClient.Mail confirm = mailpit.awaitMessageTo(newEmail, SmtpAccountEmailSubjects.CONFIRM_NEW_EMAIL);
        assertThat(confirm.text()).containsPattern("/confirm-email-change#token=[A-Za-z0-9_-]{43}");
        MailpitClient.Mail notice = mailpit.awaitMessageTo(oldEmail, SmtpAccountEmailSubjects.CHANGE_REQUESTED);
        assertThat(notice.text()).doesNotContain(newEmail);            // only a masked form of the new address
        assertThat(users.findById(id).orElseThrow().getEmail()).as("nothing changes before confirmation")
                .isEqualTo(oldEmail);
    }

    @Test
    void theConfirmLinkGoesToTheAppTheRequestCameFrom() throws Exception {
        String newEmail = uniqueEmail();
        UUID id = userWithPassword(uniqueEmail());
        String token = issuer.issue(id, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();

        mockMvc.perform(post(CHANGE).header("Authorization", "Bearer " + token)
                        .header("Origin", "https://app.getswiftdrop.me")
                        .contentType(MediaType.APPLICATION_JSON).content(body(newEmail, PASSWORD)))
                .andExpect(status().isAccepted());

        MailpitClient.Mail confirm = mailpit.awaitMessageTo(newEmail, SmtpAccountEmailSubjects.CONFIRM_NEW_EMAIL);
        assertThat(confirm.text()).contains("https://app.getswiftdrop.me/confirm-email-change#token=");
    }

    @Test
    void theDatabaseKeepsOnlyTheHashOfTheLink() throws Exception {
        String newEmail = uniqueEmail();
        UUID id = userWithPassword(uniqueEmail());

        requestChange(id, newEmail, PASSWORD).andExpect(status().isAccepted());
        mailpit.awaitMessageTo(newEmail, SmtpAccountEmailSubjects.CONFIRM_NEW_EMAIL);

        String stored = jdbc.queryForObject(
                "SELECT confirm_token_hash FROM identity.email_change_requests WHERE user_id = ?", String.class, id);
        assertThat(stored).matches("^[0-9a-f]{64}$");
    }

    @Test
    void aWrongPasswordIsRefusedAndCountedWithoutTouchingTheLoginLockout() throws Exception {
        String newEmail = uniqueEmail();
        UUID id = userWithPassword(uniqueEmail());

        requestChange(id, newEmail, "not the right password at all")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTHENTICATION_FAILED"));

        assertThat(jdbc.queryForObject("SELECT reauth_failure_count FROM identity.users WHERE id = ?", Integer.class,
                id)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT failed_login_count FROM identity.users WHERE id = ?", Integer.class, id))
                .as("a thief with a stolen token must not be able to lock the owner out of logging in").isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.email_change_requests WHERE user_id = ?",
                Integer.class, id)).isZero();
    }

    @Test
    void fiveWrongPasswordsPauseSensitiveChangesButNotLogin() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email);
        for (int attempt = 0; attempt < 5; attempt++) {
            requestChange(id, uniqueEmail(), "not the right password at all").andExpect(status().isForbidden());
        }

        requestChange(id, uniqueEmail(), PASSWORD).andExpect(status().isForbidden())   // even the right one, for now
                .andExpect(jsonPath("$.code").value("REAUTHENTICATION_FAILED"));

        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void anAddressThatAlreadyHasAnAccountGetsTheSameAnswerButNoLink() throws Exception {
        String taken = uniqueEmail();
        userWithPassword(taken);
        UUID id = userWithPassword(uniqueEmail());

        requestChange(id, taken, PASSWORD).andExpect(status().isAccepted());   // same answer: no enumeration

        mailpit.awaitMessageTo(taken, SmtpAccountEmailSubjects.ADDRESS_ALREADY_USED);
        assertThat(mailpit.countMessagesTo(taken)).as("no confirmation link to a taken address").isEqualTo(1);
    }

    @Test
    void theCurrentAddressIsNotAChange() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email);

        requestChange(id, email.toUpperCase(), PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("EMAIL_UNCHANGED"));
    }

    @Test
    void aNewRequestCancelsTheOpenOne() throws Exception {
        UUID id = userWithPassword(uniqueEmail());
        requestChange(id, uniqueEmail(), PASSWORD).andExpect(status().isAccepted());
        jdbc.update("UPDATE identity.email_change_requests SET created_at = created_at - interval '2 minutes'"
                + " WHERE user_id = ?", id);   // past the 60-second cooldown

        requestChange(id, uniqueEmail(), PASSWORD).andExpect(status().isAccepted());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.email_change_requests"
                + " WHERE user_id = ? AND cancelled_at IS NULL", Integer.class, id)).isEqualTo(1);
    }

    @Test
    void repeatedRequestsCannotFloodAnInbox() throws Exception {
        UUID id = userWithPassword(uniqueEmail());
        String victim = uniqueEmail();

        requestChange(id, victim, PASSWORD).andExpect(status().isAccepted());
        requestChange(id, victim, PASSWORD).andExpect(status().isAccepted());   // within 60 s: same answer, no mail

        mailpit.awaitMessageTo(victim, SmtpAccountEmailSubjects.CONFIRM_NEW_EMAIL);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.email_change_requests WHERE user_id = ?",
                Integer.class, id)).isEqualTo(1);
    }

    @Test
    void anAccountWithoutAPasswordMustReauthenticateAnotherWay() throws Exception {
        UUID googleOnly = transactions.execute(status -> {
            User user = new User(EmailAddress.of(uniqueEmail()), null);
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });

        requestChange(googleOnly, uniqueEmail(), "anything")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTHENTICATION_REQUIRED"));
    }

    @Test
    void aMerchantMachineTokenCannotChangeAnEmail() throws Exception {
        String machine = "Bearer " + issuer.issueForClient("swiftdrop-web", UUID.randomUUID(), List.of("MERCHANT"),
                List.of("parcel:create")).value();

        mockMvc.perform(post(CHANGE).header("Authorization", machine).contentType(MediaType.APPLICATION_JSON)
                        .content(body(uniqueEmail(), PASSWORD)))
                .andExpect(status().isForbidden());
    }

    // ---- helpers ----

    private ResultActions requestChange(UUID userId, String newEmail, String password) throws Exception {
        String token = issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        return mockMvc.perform(post(CHANGE).header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content(body(newEmail, password)));
    }

    private static String body(String newEmail, String password) {
        return "{\"new_email\":\"" + newEmail + "\",\"current_password\":\"" + password + "\"}";
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
        return "change-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
