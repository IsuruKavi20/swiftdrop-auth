package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.audit.AuditChecks;
import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Identity step 9e: the break-glass engine runs the portal's own rules and is audited as "break-glass". */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class BreakGlassRunnerIT {

    @Autowired
    private AdminUsers adminUsers;
    @Autowired
    private RoleAdministration roles;
    @Autowired
    private AuditChecks auditChecks;
    @Autowired
    private ApplicationContext context;
    @Autowired
    private UserRepository users;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private TransactionTemplate transactions;
    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void findsBlocksAndIsAuditedAsBreakGlass() {
        String email = "bg-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        UUID target = person(email, RoleName.CUSTOMER);

        assertThat(runner("find", email, "", "").execute("find")).contains(target.toString()).doesNotContain(email);
        assertThat(runner("block", target.toString(), "", "Portal down, fraud report").execute("block"))
                .contains("status=DISABLED");

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT * FROM identity.audit_log WHERE target_id = ? ORDER BY seq DESC LIMIT 1", target.toString());
        assertThat(row).containsEntry("actor_type", "BREAK_GLASS").containsEntry("action", "user.blocked");
    }

    @Test
    void theRulesStillHoldForBreakGlass() {
        UUID target = person("bg-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com",
                RoleName.CUSTOMER);

        assertThatThrownBy(() -> runner("block", target.toString(), "", "").execute("block"))
                .isInstanceOf(DomainException.class);   // no reason, no block
        assertThatThrownBy(() -> runner("grant", target.toString(), "MERCHANT", "Needed").execute("grant"))
                .isInstanceOf(DomainException.class);   // merchants only through their own approval
        assertThatThrownBy(() -> runner("nonsense", "", "", "").execute("nonsense"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void givesBackAdminRightsWhenEveryAdminIsLockedOut() {
        UUID target = person("bg-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com",
                RoleName.CUSTOMER);

        assertThat(runner("grant", target.toString(), "admin", "All admins lost access").execute("grant"))
                .contains("ADMIN");
        assertThat(runner("verify", "", "", "").execute("verify")).startsWith("audit chain OK");
    }

    private BreakGlassRunner runner(String command, String user, String role, String reason) {
        return new BreakGlassRunner(adminUsers, roles, auditChecks, context, command, user, role, reason, false);
    }

    private UUID person(String email, RoleName role) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), "{argon2}$argon2id$irrelevant");
            user.markEmailVerified();
            user.addRole(roleRepository.findByName(role).orElseThrow());
            return users.saveAndFlush(user).getId();
        });
    }
}
