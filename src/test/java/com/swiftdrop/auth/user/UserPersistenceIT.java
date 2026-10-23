package com.swiftdrop.auth.user;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class UserPersistenceIT {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void newUserGetsSafeDefaultsAndTimestamps() {
        User saved = userRepository.saveAndFlush(newUser());

        assertThat(saved.isEmailVerified()).isFalse();
        assertThat(saved.getFailedLoginCount()).isZero();
        assertThat(saved.getLockedUntil()).isNull();
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
        assertThat(saved.getVersion()).isZero();
    }

    @Test
    void eachUpdateIncrementsVersion() {
        User saved = userRepository.saveAndFlush(newUser());

        saved.markEmailVerified();
        User updated = userRepository.saveAndFlush(saved);

        assertThat(updated.getVersion()).isEqualTo(1);
    }

    @Test
    void staleCopyCannotOverwriteANewerChange() {
        UUID id = userRepository.saveAndFlush(newUser()).getId();
        User adminA = userRepository.findById(id).orElseThrow();
        User adminB = userRepository.findById(id).orElseThrow();   // separate copy, same version

        adminA.markEmailVerified();
        userRepository.saveAndFlush(adminA);                        // version 0 -> 1

        adminB.markEmailVerified();
        assertThatThrownBy(() -> userRepository.saveAndFlush(adminB)) // still thinks version is 0
                .isInstanceOf(ObjectOptimisticLockingFailureException.class);
    }

    @Test
    void databaseRejectsNegativeFailedLoginCount() {
        assertThatThrownBy(() -> jdbcTemplate.update(
                "INSERT INTO identity.users (email, failed_login_count) VALUES (?, -1)",
                "neg-" + UUID.randomUUID() + "@example.com"))
                .rootCause().hasMessageContaining("ck_users_failed_login_count");
    }

    @Test
    void oauthAccountsHasAnIndexOnUserId() {
        Integer indexes = jdbcTemplate.queryForObject("""
                SELECT count(*) FROM pg_indexes
                WHERE schemaname = 'identity' AND indexname = 'ix_oauth_accounts_user_id'""", Integer.class);

        assertThat(indexes).isEqualTo(1);
    }

    private static User newUser() {
        return new User(EmailAddress.of("user-" + UUID.randomUUID() + "@example.com"), "$argon2id$test");
    }
}
