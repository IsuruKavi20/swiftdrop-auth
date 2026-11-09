package com.swiftdrop.auth.audit;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AuditUnitTest {

    private static final Instant AT = Instant.parse("2026-11-10T08:00:00.123456Z");

    @Test
    void csvCellsCanNeverRunAsFormulas() {
        assertThat(AuditQueries.csvField("=HYPERLINK(\"x\")")).isEqualTo("\"'=HYPERLINK(\"\"x\"\")\"");
        assertThat(AuditQueries.csvField("+1")).isEqualTo("\"'+1\"");
        assertThat(AuditQueries.csvField("@SUM(A1)")).startsWith("\"'@");
        assertThat(AuditQueries.csvField("plain")).isEqualTo("\"plain\"");
        assertThat(AuditQueries.csvField(null)).isEmpty();
    }

    @Test
    void theHashCoversEveryFieldAndTheLink() {
        AuditChain.Row row = row("user.blocked", null);
        String hash = AuditChain.hash(AuditChain.GENESIS, row);

        assertThat(hash).hasSize(64).isEqualTo(AuditChain.hash(AuditChain.GENESIS, row));
        assertThat(AuditChain.hash("1".repeat(64), row)).isNotEqualTo(hash);
        assertThat(AuditChain.hash(AuditChain.GENESIS, row("user.unblocked", null))).isNotEqualTo(hash);
        // A missing field and an empty one are different rows
        assertThat(AuditChain.hash(AuditChain.GENESIS, row("user.blocked", ""))).isNotEqualTo(hash);
    }

    @Test
    void anActorIsOnlyThemselvesWhenTheyAreThatPerson() {
        UUID person = UUID.randomUUID();
        assertThat(Actor.user(person).is(person)).isTrue();
        assertThat(Actor.user(UUID.randomUUID()).is(person)).isFalse();
        assertThat(Actor.breakGlass().is(person)).isFalse();
    }

    private static AuditChain.Row row(String action, String ip) {
        return new AuditChain.Row(7, AT, "USER", "abc", action, "user", "def", ip, "req-1", "{}");
    }
}
