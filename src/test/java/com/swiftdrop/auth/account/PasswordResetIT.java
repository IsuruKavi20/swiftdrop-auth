package com.swiftdrop.auth.account;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.MailpitClient;
import com.swiftdrop.auth.TestcontainersConfiguration;
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

import java.time.Duration;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 11a: forgot password (emailed one-time link, 30 minutes, every session ends). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PasswordResetIT {

    private static final String REQUEST = "/api/v1/auth/password-reset";
    private static final String CONFIRM = "/api/v1/auth/password-reset/confirm";
    private static final String OLD_PASSWORD = "my parcel arrives on tuesday";
    private static final String NEW_PASSWORD = "a brand new and much longer passphrase";
    private static final Pattern LINK_TOKEN = Pattern.compile("#token=([A-Za-z0-9_-]{43})");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private MailpitClient mailpit;

    @Test
    void theLinkSetsANewPasswordAndEndsEverySession() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email, OLD_PASSWORD);
        String oldRefresh = refreshTokenFrom(login(email, OLD_PASSWORD));

        requestReset(email).andExpect(status().isAccepted());
        confirm(tokenFromEmail(email), NEW_PASSWORD).andExpect(status().isNoContent());

        login(email, NEW_PASSWORD).andExpect(status().isOk());
        login(email, OLD_PASSWORD).andExpect(status().isUnauthorized());
        refresh(oldRefresh).andExpect(status().isUnauthorized());
        mailpit.awaitMessageTo(email, SmtpAccountEmailSubjects.PASSWORD_CHANGED);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.audit_log WHERE action = 'password.reset'"
                + " AND target_id = ?", Integer.class, id.toString())).isEqualTo(1);
    }

    @Test
    void anUnknownEmailGetsTheSameAnswerAndNoMail() throws Exception {
        String email = uniqueEmail();

        requestReset(email).andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value(PasswordResetMessages.ACCEPTED));

        Thread.sleep(Duration.ofSeconds(2));
        assertThat(mailpit.countMessagesTo(email)).isZero();
    }

    @Test
    void theLinkWorksOnlyOnce() throws Exception {
        String email = uniqueEmail();
        userWithPassword(email, OLD_PASSWORD);
        requestReset(email);
        String token = tokenFromEmail(email);

        confirm(token, NEW_PASSWORD).andExpect(status().isNoContent());
        confirm(token, "yet another long passphrase for me").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_OR_EXPIRED_TOKEN"));

        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void anExpiredLinkIsRefused() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email, OLD_PASSWORD);
        requestReset(email);
        String token = tokenFromEmail(email);
        jdbc.update("UPDATE identity.password_reset_tokens SET expires_at = now() - interval '1 minute'"
                + " WHERE user_id = ?", id);

        confirm(token, NEW_PASSWORD).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_OR_EXPIRED_TOKEN"));
        login(email, OLD_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void aWeakPasswordIsRefusedAndTheLinkStillWorks() throws Exception {
        String email = uniqueEmail();
        userWithPassword(email, OLD_PASSWORD);
        requestReset(email);
        String token = tokenFromEmail(email);

        confirm(token, "short").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("WEAK_PASSWORD"));
        confirm(token, NEW_PASSWORD).andExpect(status().isNoContent());
    }

    @Test
    void aGarbageTokenIsRefused() throws Exception {
        confirm("not-a-real-token", NEW_PASSWORD).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_OR_EXPIRED_TOKEN"));
    }

    @Test
    void repeatedRequestsSendOnlyOneEmailPerMinute() throws Exception {
        String email = uniqueEmail();
        userWithPassword(email, OLD_PASSWORD);

        requestReset(email).andExpect(status().isAccepted());
        tokenFromEmail(email);
        requestReset(email).andExpect(status().isAccepted());

        Thread.sleep(Duration.ofSeconds(2));
        assertThat(mailpit.countMessagesTo(email)).isEqualTo(1);
    }

    @Test
    void aGoogleOnlyAccountCanAddAPassword() throws Exception {
        String email = uniqueEmail();
        userWithPassword(email, null);

        requestReset(email);
        confirm(tokenFromEmail(email), NEW_PASSWORD).andExpect(status().isNoContent());

        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void aBlockedAccountGetsNoLink() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email, OLD_PASSWORD);
        transactions.executeWithoutResult(status -> users.findById(id).orElseThrow().disable());

        requestReset(email).andExpect(status().isAccepted());

        Thread.sleep(Duration.ofSeconds(2));
        assertThat(mailpit.countMessagesTo(email)).isZero();
    }

    @Test
    void aResetAlsoLiftsTheFailedLoginLock() throws Exception {
        String email = uniqueEmail();
        UUID id = userWithPassword(email, OLD_PASSWORD);
        jdbc.update("UPDATE identity.users SET locked_until = now() + interval '1 hour', failed_login_count = 10"
                + " WHERE id = ?", id);

        requestReset(email);
        confirm(tokenFromEmail(email), NEW_PASSWORD).andExpect(status().isNoContent());

        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    // ---- helpers ----

    private ResultActions requestReset(String email) throws Exception {
        return mockMvc.perform(post(REQUEST).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\"}"));
    }

    private ResultActions confirm(String token, String newPassword) throws Exception {
        return mockMvc.perform(post(CONFIRM).contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\",\"new_password\":\"" + newPassword + "\"}"));
    }

    private String tokenFromEmail(String email) {
        MailpitClient.Mail mail = mailpit.awaitMessageTo(email, SmtpAccountEmailSubjects.PASSWORD_RESET);
        Matcher link = LINK_TOKEN.matcher(mail.text());
        assertThat(link.find()).as("reset link in: %s", mail.text()).isTrue();
        return link.group(1);
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

    private UUID userWithPassword(String email, String password) {
        String hash = password == null ? null : encoder.encode(password);
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), hash);
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });
    }

    private static String uniqueEmail() {
        return "reset-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
