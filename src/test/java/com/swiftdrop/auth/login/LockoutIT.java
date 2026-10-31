package com.swiftdrop.auth.login;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Per-account throttling (deep dive 26, section 4): progressive, temporary, invisible to the attacker. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class LockoutIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final String WRONG = "a completely wrong passphrase";

    @Autowired
    private LoginService login;

    @Autowired
    private UserRepository users;

    @Autowired
    private RoleRepository roles;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void fiveWrongPasswordsLockTheAccountForAboutAMinuteWithTheSameAnswer() {
        String email = verifiedUser();
        failTimes(email, 5);

        assertThat(failedCount(email)).isEqualTo(5);
        assertThat(lockedFor(email)).isBetween(Duration.ofSeconds(50), Duration.ofSeconds(61));
        // The correct password does not open a locked account, and the answer looks like any wrong password
        assertThatThrownBy(() -> login.login(email, PASSWORD)).isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void moreFailuresMeanLongerLocksUpToFifteenMinutes() {
        String email = verifiedUser();

        failTimes(email, 5);
        // past the threshold, every guess re-locks: one guess per lock window
        for (int i = 0; i < 5; i++) {
            endLock(email);
            failTimes(email, 1);
        }
        assertThat(failedCount(email)).isEqualTo(10);
        assertThat(lockedFor(email)).isBetween(Duration.ofMinutes(4), Duration.ofMinutes(5).plusSeconds(1));

        for (int i = 0; i < 5; i++) {
            endLock(email);
            failTimes(email, 1);
        }
        assertThat(lockedFor(email)).isBetween(Duration.ofMinutes(14), Duration.ofMinutes(15).plusSeconds(1));
    }

    @Test
    void guessesDuringALockDoNotExtendIt() {
        String email = verifiedUser();
        failTimes(email, 5);
        Duration before = lockedFor(email);

        failTimes(email, 20);   // a stranger keeps trying while locked

        assertThat(failedCount(email)).isEqualTo(5);
        assertThat(lockedFor(email)).isLessThanOrEqualTo(before);
    }

    @Test
    void failuresFromLongAgoAreForgotten() {
        String email = verifiedUser();
        failTimes(email, 4);
        jdbc.update("UPDATE identity.users SET last_failed_login_at = now() - interval '2 hours' WHERE email = ?", email);

        failTimes(email, 1);

        assertThat(failedCount(email)).isEqualTo(1);   // starts again: old typos don't add up over months
    }

    @Test
    void afterTheLockEndsTheCorrectPasswordWorksAndResetsTheCounter() {
        String email = verifiedUser();
        failTimes(email, 5);
        jdbc.update("UPDATE identity.users SET locked_until = now() - interval '1 second' WHERE email = ?", email);

        assertThat(login.login(email, PASSWORD).accessToken().value()).isNotBlank();

        assertThat(failedCount(email)).isZero();
        assertThat(jdbc.queryForObject("SELECT locked_until FROM identity.users WHERE email = ?", Timestamp.class, email))
                .isNull();
    }

    @Test
    void aFewMistakesBelowTheThresholdDoNotLock() {
        String email = verifiedUser();
        failTimes(email, 4);

        assertThat(login.login(email, PASSWORD).accessToken().value()).isNotBlank();
        assertThat(failedCount(email)).isZero();
    }

    @Test
    void parallelWrongGuessesAreAllCounted() throws Exception {
        String email = verifiedUser();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(5);
        try {
            List<Future<?>> runs = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                runs.add(pool.submit(() -> {
                    start.await();
                    try {
                        login.login(email, WRONG);
                    } catch (InvalidCredentialsException expected) {
                        // every guess fails
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> run : runs) {
                run.get();
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(failedCount(email)).isEqualTo(5);   // atomic increments: none lost
    }

    private void failTimes(String email, int times) {
        for (int i = 0; i < times; i++) {
            assertThatThrownBy(() -> login.login(email, WRONG)).isInstanceOf(InvalidCredentialsException.class);
        }
    }

    private void endLock(String email) {
        jdbc.update("UPDATE identity.users SET locked_until = now() - interval '1 second' WHERE email = ?", email);
    }

    private int failedCount(String email) {
        return jdbc.queryForObject("SELECT failed_login_count FROM identity.users WHERE email = ?", Integer.class, email);
    }

    private Duration lockedFor(String email) {
        Timestamp until = jdbc.queryForObject("SELECT locked_until FROM identity.users WHERE email = ?",
                Timestamp.class, email);
        return Duration.between(Instant.now(), until.toInstant());
    }

    private String verifiedUser() {
        String email = "lock-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        String hash = encoder.encode(PASSWORD);
        transactions.executeWithoutResult(status -> {
            User user = new User(EmailAddress.of(email), hash);
            user.addRole(roles.findByName(RoleName.CUSTOMER).orElseThrow());
            user.markEmailVerified();
            users.saveAndFlush(user);
        });
        return email;
    }
}
