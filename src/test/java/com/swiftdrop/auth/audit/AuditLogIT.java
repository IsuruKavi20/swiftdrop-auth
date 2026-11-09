package com.swiftdrop.auth.audit;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Identity step 9a: the audit log is append-only (for the app's role and, by trigger, for everyone) and
 * tamper-evident (a hash chain: changing, removing or inserting a row is found by verify).
 */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class AuditLogIT {

    @Autowired
    private AuditLog audit;
    @Autowired
    private AuditChecks checks;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private TransactionTemplate tx;
    @Autowired
    private JsonMapper json;
    @Autowired
    private PostgreSQLContainer postgres;

    private JdbcTemplate superuser;

    @BeforeEach
    void emptyLog() {
        superuser = new JdbcTemplate(new DriverManagerDataSource(postgres.getJdbcUrl(), postgres.getUsername(),
                postgres.getPassword()));
        asSuperuserWithoutTriggers("DELETE FROM identity.audit_log",
                "UPDATE identity.audit_checkpoint SET seq = 0, hash = repeat('0', 64)");
    }

    @Test
    void rowsAreChainedAndVerify() {
        UUID person = UUID.randomUUID();
        record(AuditEntry.onUser(Actor.user(UUID.randomUUID()), "role.granted", person, Map.of("role", "DISPATCHER")));
        record(AuditEntry.onUser(Actor.system(), "erasure.completed", person, Map.of()));

        List<Map<String, Object>> rows = jdbc.queryForList("SELECT * FROM identity.audit_log ORDER BY seq");
        assertThat(rows).hasSize(2);
        assertThat(rows.get(0).get("prev_hash")).isEqualTo(AuditChain.GENESIS);
        assertThat(rows.get(1).get("prev_hash")).isEqualTo(rows.get(0).get("hash"));
        assertThat(rows.get(0).get("details")).isEqualTo("{\"role\":\"DISPATCHER\"}");
        assertThat(rows.get(0).get("target_id")).isEqualTo(person.toString());

        AuditVerification result = checks.verify();
        assertThat(result.ok()).isTrue();
        assertThat(result.rowsChecked()).isEqualTo(2);
        assertThat(result.lastHash()).isEqualTo(rows.get(1).get("hash"));
    }

    @Test
    void recordingOutsideATransactionFails() {
        AuditEntry entry = AuditEntry.onUser(Actor.system(), "user.blocked", UUID.randomUUID(), Map.of());
        assertThatThrownBy(() -> audit.record(entry)).isInstanceOf(IllegalTransactionStateException.class);
    }

    @Test
    void personalDataAndOddActionNamesAreRefused() {
        UUID person = UUID.randomUUID();
        assertThatThrownBy(() -> AuditEntry.onUser(Actor.system(), "email-change.requested", person,
                Map.of("to", "someone@example.com"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AuditEntry.onUser(Actor.system(), "Not An Action", person, Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theAppCannotChangeOrRemoveRows() {
        record(AuditEntry.onUser(Actor.system(), "user.blocked", UUID.randomUUID(), Map.of()));

        assertThatThrownBy(() -> jdbc.update("UPDATE identity.audit_log SET action = 'user.unblocked'"))
                .isInstanceOf(DataAccessException.class).rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> jdbc.update("DELETE FROM identity.audit_log"))
                .isInstanceOf(DataAccessException.class).rootCause().hasMessageContaining("append-only");
        assertThatThrownBy(() -> jdbc.execute("TRUNCATE identity.audit_log"))
                .isInstanceOf(DataAccessException.class);
    }

    @Test
    void evenTheSuperuserCannotChangeRowsWhileTheTriggerIsOn() {
        record(AuditEntry.onUser(Actor.system(), "user.blocked", UUID.randomUUID(), Map.of()));

        assertThatThrownBy(() -> superuser.update("UPDATE identity.audit_log SET action = 'user.unblocked'"))
                .isInstanceOf(DataAccessException.class).rootCause().hasMessageContaining("append-only");
    }

    @Test
    void verifyFindsAChangedRow() {
        recordThree();
        long middle = jdbc.queryForObject("SELECT seq FROM identity.audit_log ORDER BY seq OFFSET 1 LIMIT 1", Long.class);

        asSuperuserWithoutTriggers("UPDATE identity.audit_log SET action = 'user.unblocked' WHERE seq = " + middle);

        AuditVerification result = checks.verify();
        assertThat(result.ok()).isFalse();
        assertThat(result.firstBrokenSeq()).isEqualTo(middle);
    }

    @Test
    void verifyFindsARemovedRow() {
        recordThree();
        List<Long> seqs = jdbc.queryForList("SELECT seq FROM identity.audit_log ORDER BY seq", Long.class);

        asSuperuserWithoutTriggers("DELETE FROM identity.audit_log WHERE seq = " + seqs.get(1));

        assertThat(checks.verify().firstBrokenSeq()).isEqualTo(seqs.get(2));
    }

    @Test
    void parallelWritersBuildOneUnbrokenChain() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Callable<Void>> writers = IntStream.range(0, 40).<Callable<Void>>mapToObj(i -> () -> {
                record(AuditEntry.onUser(Actor.system(), "user.blocked", UUID.randomUUID(), Map.of("n", i)));
                return null;
            }).toList();
            for (Future<Void> done : pool.invokeAll(writers)) {
                done.get();
            }
        } finally {
            pool.shutdownNow();
        }

        AuditVerification result = checks.verify();
        assertThat(result.ok()).isTrue();
        assertThat(result.rowsChecked()).isEqualTo(40);
    }

    @Test
    void retentionRemovesRowsOlderThanAYearAndTheChainStillVerifies() {
        AuditLog lastYear = new AuditLog(jdbc, json,
                Clock.fixed(Instant.now().minus(400, ChronoUnit.DAYS), ZoneOffset.UTC));
        tx.executeWithoutResult(status -> {
            lastYear.record(AuditEntry.onUser(Actor.system(), "user.blocked", UUID.randomUUID(), Map.of()));
            lastYear.record(AuditEntry.onUser(Actor.system(), "user.unblocked", UUID.randomUUID(), Map.of()));
        });
        String lastOldHash = jdbc.queryForObject("SELECT hash FROM identity.audit_log ORDER BY seq DESC LIMIT 1",
                String.class);
        record(AuditEntry.onUser(Actor.system(), "user.blocked", UUID.randomUUID(), Map.of()));

        assertThat(checks.removeExpired()).isEqualTo(2);

        assertThat(jdbc.queryForObject("SELECT hash FROM identity.audit_checkpoint", String.class))
                .isEqualTo(lastOldHash);
        AuditVerification result = checks.verify();
        assertThat(result.ok()).isTrue();
        assertThat(result.rowsChecked()).isEqualTo(1);
        assertThat(checks.removeExpired()).isZero();
    }

    private void recordThree() {
        for (int i = 0; i < 3; i++) {
            record(AuditEntry.onUser(Actor.system(), "user.blocked", UUID.randomUUID(), Map.of()));
        }
    }

    private void record(AuditEntry entry) {
        tx.executeWithoutResult(status -> audit.record(entry));
    }

    // Plays an attacker (or a test reset) with full database rights who also switches the trigger off
    private void asSuperuserWithoutTriggers(String... statements) {
        new TransactionTemplate(new DataSourceTransactionManager(superuser.getDataSource()))
                .executeWithoutResult(status -> {
                    superuser.execute("SET LOCAL session_replication_role = replica");
                    for (String statement : statements) {
                        superuser.execute(statement);
                    }
                });
    }
}
