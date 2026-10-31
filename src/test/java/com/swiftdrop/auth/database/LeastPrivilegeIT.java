package com.swiftdrop.auth.database;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class LeastPrivilegeIT {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void appUserIsNotSuperuser() {
        Boolean superuser = jdbcTemplate.queryForObject(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user", Boolean.class);

        assertThat(superuser).isFalse();
    }

    @Test
    void appUserCanReadRows() {
        Integer roles = jdbcTemplate.queryForObject("SELECT count(*) FROM identity.roles", Integer.class);

        assertThat(roles).isPositive();
    }

    @Test
    void appUserCannotDropTables() {
        assertThatThrownBy(() -> jdbcTemplate.execute("DROP TABLE identity.users"))
                .isInstanceOf(DataAccessException.class)
                .rootCause().hasMessageContaining("must be owner");
    }

    @Test
    void appUserCannotCreateTables() {
        assertThatThrownBy(() -> jdbcTemplate.execute("CREATE TABLE identity.intruder (x int)"))
                .isInstanceOf(DataAccessException.class)
                .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void appUserCannotTruncateTables() {
        assertThatThrownBy(() -> jdbcTemplate.execute("TRUNCATE identity.users"))
                .isInstanceOf(DataAccessException.class)
                .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void appUserCannotTouchFlywayHistory() {
        assertThatThrownBy(() -> jdbcTemplate.update("DELETE FROM identity.flyway_schema_history"))
                .isInstanceOf(DataAccessException.class)
                .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void appUserCannotCreateObjectsInPublicSchema() {
        assertThatThrownBy(() -> jdbcTemplate.execute("CREATE TABLE public.intruder (x int)"))
                .isInstanceOf(DataAccessException.class)
                .rootCause().hasMessageContaining("permission denied");
    }
}
