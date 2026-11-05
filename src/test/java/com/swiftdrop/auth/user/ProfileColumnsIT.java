package com.swiftdrop.auth.user;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** V11: the identity profile columns, and the database rules that back up the Java validation. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class ProfileColumnsIT {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void existingAccountsKeepWorkingWithAnEmptyProfile() {
        UUID id = savedUser();

        Map<String, Object> row = jdbcTemplate.queryForMap(
                "SELECT name, given_name, family_name, picture_url, locale, profile_source, profile_updated_at"
                        + " FROM users WHERE id = ?", id);

        assertThat(row.values()).containsOnlyNulls();
    }

    @Test
    void storesAFullProfile() {
        UUID id = savedUser();

        jdbcTemplate.update("UPDATE users SET name = ?, given_name = ?, family_name = ?, picture_url = ?,"
                        + " locale = ?, profile_source = 'GOOGLE', profile_updated_at = now() WHERE id = ?",
                "ඉසුරු කවින්ද", "ඉසුරු", "කවින්ද", "https://lh3.googleusercontent.com/a/x", "si-LK", id);

        assertThat(jdbcTemplate.queryForObject("SELECT name FROM users WHERE id = ?", String.class, id))
                .isEqualTo("ඉසුරු කවින්ද");
    }

    @Test
    void pictureMustBeHttps() {
        UUID id = savedUser();

        assertThatThrownBy(() -> jdbcTemplate.update(
                "UPDATE users SET picture_url = 'http://evil.example/x.png' WHERE id = ?", id))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbcTemplate.update(
                "UPDATE users SET picture_url = 'javascript:alert(1)' WHERE id = ?", id))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void profileSourceIsOnlyUserOrGoogle() {
        UUID id = savedUser();

        assertThatThrownBy(() -> jdbcTemplate.update("UPDATE users SET profile_source = 'ADMIN' WHERE id = ?", id))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void nameCannotBeBlankWhenPresent() {
        UUID id = savedUser();

        assertThatThrownBy(() -> jdbcTemplate.update("UPDATE users SET name = '   ' WHERE id = ?", id))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private UUID savedUser() {
        String email = "profile-" + UUID.randomUUID() + "@example.com";
        return userRepository.saveAndFlush(new User(EmailAddress.of(email), null)).getId();
    }
}
