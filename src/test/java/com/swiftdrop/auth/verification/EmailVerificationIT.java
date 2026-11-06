package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.MailpitClient;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.signup.SignupService;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** End to end with real Postgres + real (fake) mail server: signup → email → verify. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class EmailVerificationIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final Pattern TOKEN_IN_LINK =
            Pattern.compile("http://localhost:3000/verify-email#token=([A-Za-z0-9_-]{43})");

    @Autowired
    private SignupService signup;

    @Autowired
    private EmailVerificationService verification;

    @Autowired
    private UserRepository users;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private MailpitClient mailpit;

    @Test
    void signupSendsAOneTimeLinkThatVerifiesTheAccount() {
        String email = uniqueEmail();
        signup.signUp("Test User", email, PASSWORD);

        MailpitClient.Mail mail = mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT);
        String token = tokenFrom(mail.text());
        assertThat(users.findByEmail(email).orElseThrow().isEmailVerified()).isFalse();

        verification.verify(token);

        assertThat(users.findByEmail(email).orElseThrow().isEmailVerified()).isTrue();
        assertThatThrownBy(() -> verification.verify(token)).isInstanceOf(InvalidVerificationTokenException.class);
    }

    @Test
    void databaseStoresOnlyTheHashOfTheToken() {
        String email = uniqueEmail();
        signup.signUp("Test User", email, PASSWORD);
        String token = tokenFrom(mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT).text());

        String stored = jdbc.queryForObject("""
                SELECT t.token_hash FROM identity.email_verification_tokens t
                JOIN identity.users u ON u.id = t.user_id WHERE u.email = ?""", String.class, email);

        assertThat(stored).isEqualTo(VerificationTokens.hash(token)).doesNotContain(token);
    }

    @Test
    void signingUpAgainWithAVerifiedEmailSendsAlreadyRegisteredMail() {
        String email = uniqueEmail();
        signup.signUp("Test User", email, PASSWORD);
        verification.verify(tokenFrom(mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT).text()));

        signup.signUp("Test User", email, "a completely different passphrase");

        MailpitClient.Mail mail = mailpit.awaitMessageTo(email, SmtpAccountEmailSender.ALREADY_REGISTERED_SUBJECT);
        assertThat(mail.text()).contains("http://localhost:3000/login").doesNotContain("verify-email");
    }

    @Test
    void resendIssuesANewLinkAndTheOldOneStopsWorking() {
        String email = uniqueEmail();
        signup.signUp("Test User", email, PASSWORD);
        String first = tokenFrom(mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT).text());

        verification.requestResend(email);
        String second = awaitSecondToken(email, first);

        assertThatThrownBy(() -> verification.verify(first)).isInstanceOf(InvalidVerificationTokenException.class);
        verification.verify(second);
        assertThat(users.findByEmail(email).orElseThrow().isEmailVerified()).isTrue();
    }

    @Test
    void outboxRecordsEveryEmailAsCompleted() {
        String email = uniqueEmail();
        signup.signUp("Test User", email, PASSWORD);
        mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT);

        Integer open = jdbc.queryForObject(
                "SELECT count(*) FROM identity.event_publication WHERE completion_date IS NULL", Integer.class);
        assertThat(open).isZero();
    }

    private String awaitSecondToken(String email, String first) {
        long deadline = System.nanoTime() + 15_000_000_000L;
        while (System.nanoTime() < deadline) {
            if (mailpit.countMessagesTo(email) >= 2) {
                String latest = tokenFrom(mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT).text());
                if (!latest.equals(first)) {
                    return latest;
                }
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("second verification email did not arrive");
    }

    private static String tokenFrom(String text) {
        Matcher matcher = TOKEN_IN_LINK.matcher(text);
        assertThat(matcher.find()).as("verification link in email body").isTrue();
        return matcher.group(1);
    }

    private static String uniqueEmail() {
        return "verify-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
