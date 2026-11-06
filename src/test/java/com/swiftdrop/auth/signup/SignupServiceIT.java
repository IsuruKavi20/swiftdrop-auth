package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class SignupServiceIT {

    private static final int CONCURRENT_SIGNUPS = 5;
    private static final long TIMEOUT_SECONDS = 30;

    @Autowired
    private SignupService signupService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void savesNormalisedUserWithCustomerRole() {
        String id = uniqueId();
        signupService.signUp("Test User", "  Ｓaved-" + id + "@Example.com ", "a long passphrase here");

        String role = jdbcTemplate.queryForObject("""
                SELECT r.name FROM identity.users u
                JOIN identity.user_roles ur ON ur.user_id = u.id
                JOIN identity.roles r ON r.id = ur.role_id
                WHERE u.email = ?""", String.class, "saved-" + id + "@example.com");
        assertThat(role).isEqualTo("CUSTOMER");
    }

    @Test
    void savesTheNameAsTheUsersOwnProfile() {
        String email = "named-" + uniqueId() + "@example.com";
        signupService.signUp("  ඉසුරු   කවින්ද ", email, "a long passphrase here");

        var row = jdbcTemplate.queryForMap(
                "SELECT name, profile_source, profile_updated_at FROM identity.users WHERE email = ?", email);
        assertThat(row.get("name")).isEqualTo("ඉසුරු කවින්ද");
        assertThat(row.get("profile_source")).isEqualTo("USER");
        assertThat(row.get("profile_updated_at")).isNotNull();
    }

    @Test
    void sameEmailWithDifferentCaseIsADuplicate() {
        String id = uniqueId();
        signupService.signUp("Test User", "case-" + id + "@example.com", "a long passphrase here");

        assertThat(signupService.signUp("Test User", "CASE-" + id + "@Example.COM", "a long passphrase here"))
                .isEqualTo(SignupOutcome.EMAIL_ALREADY_REGISTERED);
    }

    @Test
    void weakPasswordIsRejectedIdenticallyForNewAndExistingEmails() {
        String existing = "exists-" + uniqueId() + "@example.com";
        signupService.signUp("Test User", existing, "a long passphrase here");

        for (String weak : new String[] {"short", "swiftdrop swiftdrop"}) {
            WeakPasswordException forExisting = catchWeak(existing, weak);
            WeakPasswordException forNew = catchWeak("new-" + uniqueId() + "@example.com", weak);
            assertThat(forExisting.reason()).isEqualTo(forNew.reason());
            assertThat(forExisting.violations()).isEqualTo(forNew.violations());
        }
    }

    private WeakPasswordException catchWeak(String email, String password) {
        try {
            signupService.signUp("Test User", email, password);
        } catch (WeakPasswordException e) {
            return e;
        }
        throw new AssertionError("expected the password to be rejected");
    }

    @Test
    void databaseRejectsEmailsThatAreNotLowercase() {
        assertThatThrownBy(() -> jdbcTemplate.update(
                "INSERT INTO identity.users (email) VALUES ('Mixed@Example.com')"))
                .rootCause().hasMessageContaining("ck_users_email_lowercase");
    }

    @Test
    void concurrentSignupsWithSameEmailCreateExactlyOneUser() throws Exception {
        String email = "race-" + uniqueId() + "@example.com";
        CountDownLatch startTogether = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();

        try (ExecutorService pool = Executors.newFixedThreadPool(CONCURRENT_SIGNUPS)) {
            for (int i = 0; i < CONCURRENT_SIGNUPS; i++) {
                results.add(pool.submit(() -> {
                    startTogether.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    return signupService.signUp("Test User", email, "a long passphrase here") == SignupOutcome.ACCOUNT_CREATED;
                }));
            }
            startTogether.countDown();

            long successes = 0;
            for (Future<Boolean> result : results) {
                if (result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    successes++;
                }
            }
            assertThat(successes).isEqualTo(1);
        }
        assertThat(userRepository.existsByEmail(email)).isTrue();
        assertThat(jdbcTemplate.queryForObject(
                "SELECT count(*) FROM identity.users WHERE email = ?", Integer.class, email)).isEqualTo(1);
    }

    private static String uniqueId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
