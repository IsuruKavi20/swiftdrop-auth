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
        signupService.signUp("  Ｓaved-" + id + "@Example.com ", "a long passphrase here");

        String role = jdbcTemplate.queryForObject("""
                SELECT r.name FROM identity.users u
                JOIN identity.user_roles ur ON ur.user_id = u.id
                JOIN identity.roles r ON r.id = ur.role_id
                WHERE u.email = ?""", String.class, "saved-" + id + "@example.com");
        assertThat(role).isEqualTo("CUSTOMER");
    }

    @Test
    void sameEmailWithDifferentCaseIsADuplicate() {
        String id = uniqueId();
        signupService.signUp("case-" + id + "@example.com", "a long passphrase here");

        assertThatThrownBy(() -> signupService.signUp("CASE-" + id + "@Example.COM", "a long passphrase here"))
                .isInstanceOf(EmailAlreadyUsedException.class);
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
                    try {
                        signupService.signUp(email, "a long passphrase here");
                        return true;
                    } catch (EmailAlreadyUsedException duplicate) {
                        return false;
                    }
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
