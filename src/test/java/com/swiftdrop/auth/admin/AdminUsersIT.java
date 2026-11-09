package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Identity steps 9a-9c: the SwiftDrop admin portal blocks, unblocks and deletes people with the admin's own token,
 * reads the audit log, and every action leaves one audit row naming the admin.
 */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminUsersIT {

    private static final String USERS = "/api/v1/admin/users/";
    private static final String AUDIT = "/api/v1/admin/audit";
    private static final List<String> ADMIN_PERMISSIONS = List.of("user:read", "user:manage-roles",
            "user:manage-status", "user:delete", "audit:read");

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private AccessTokenIssuer issuer;
    @Autowired
    private UserRepository users;
    @Autowired
    private RoleRepository roles;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private TransactionTemplate transactions;

    private final UUID adminId = UUID.randomUUID();

    @Test
    void blockingEndsSessionsTellsReceiversAndIsAudited() throws Exception {
        UUID target = person(RoleName.CUSTOMER);
        openSession(target);

        reasoned(post(USERS + target + "/block"), "Reported for fraud, ticket 4411")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DISABLED"))
                .andExpect(jsonPath("$.activeSessions").value(0))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        assertThat(statusOf(target)).isEqualTo("DISABLED");
        assertThat(eventTypes(target)).anyMatch(type -> type.endsWith("/account-disabled"));
        Map<String, Object> row = lastAudit(target);
        assertThat(row).containsEntry("action", "user.blocked").containsEntry("actor_type", "USER")
                .containsEntry("actor_id", adminId.toString());
        assertThat((String) row.get("details")).contains("ticket 4411");
    }

    @Test
    void unblockingBringsThePersonBack() throws Exception {
        UUID target = person(RoleName.CUSTOMER);
        reasoned(post(USERS + target + "/block"), "Checking a report");

        reasoned(post(USERS + target + "/unblock"), "Report was wrong")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        assertThat(eventTypes(target)).anyMatch(type -> type.endsWith("/account-enabled"));
        assertThat(lastAudit(target)).containsEntry("action", "user.unblocked");
    }

    @Test
    void adminsNeverBlockOrDeleteThemselves() throws Exception {
        reasoned(post(USERS + adminId + "/block"), "Testing myself")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("CANNOT_ACT_ON_SELF"));
        reasoned(delete(USERS + adminId), "Testing myself")
                .andExpect(status().isForbidden());
    }

    @Test
    void theLastActiveAdminCannotBeBlocked() throws Exception {
        jdbc.update("DELETE FROM identity.user_roles WHERE role_id = (SELECT id FROM identity.roles WHERE name = 'ADMIN')");
        UUID onlyAdmin = person(RoleName.ADMIN);

        reasoned(post(USERS + onlyAdmin + "/block"), "Trying to lock everyone out")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("LAST_ADMIN"));
        assertThat(statusOf(onlyAdmin)).isEqualTo("ACTIVE");

        UUID secondAdmin = person(RoleName.ADMIN);
        reasoned(post(USERS + onlyAdmin + "/block"), "Now there is another admin").andExpect(status().isOk());
        reasoned(delete(USERS + secondAdmin), "Would leave no active admin")
                .andExpect(status().isConflict());
    }

    @Test
    void adminDeleteStartsTheErasureAndIsAudited() throws Exception {
        UUID target = person(RoleName.COURIER);

        reasoned(delete(USERS + target), "Owner asked by phone, ticket 77").andExpect(status().isNoContent());

        assertThat(statusOf(target)).isEqualTo("DELETED");
        assertThat(eventTypes(target)).anyMatch(type -> type.endsWith("/account-purged"));
        Map<String, Object> row = lastAudit(target);
        assertThat(row).containsEntry("action", "account.deleted").containsEntry("actor_id", adminId.toString());
        assertThat((String) row.get("details")).contains("\"by\":\"admin\"");
        mockMvc.perform(get(USERS + target).header("Authorization", admin()))
                .andExpect(status().isNotFound());
    }

    @Test
    void aReasonIsRequiredAndMayNotHoldAnEmailAddress() throws Exception {
        UUID target = person(RoleName.CUSTOMER);

        reasoned(post(USERS + target + "/block"), "").andExpect(status().isBadRequest());
        reasoned(post(USERS + target + "/block"), "mail from someone@example.com").andExpect(status().isBadRequest());
        assertThat(statusOf(target)).isEqualTo("ACTIVE");
    }

    @Test
    void withoutThePermissionNothingHappens() throws Exception {
        UUID target = person(RoleName.CUSTOMER);
        String dispatcher = "Bearer " + issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("DISPATCHER"),
                List.of("parcel:read-all", "user:read")).value();

        mockMvc.perform(post(USERS + target + "/block").header("Authorization", dispatcher)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"no right\"}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get(AUDIT).header("Authorization", dispatcher)).andExpect(status().isForbidden());
        assertThat(statusOf(target)).isEqualTo("ACTIVE");
    }

    @Test
    void detailShowsWhatTheScreenNeedsOnly() throws Exception {
        UUID target = person(RoleName.CUSTOMER);
        openSession(target);

        mockMvc.perform(get(USERS + target).header("Authorization", admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(target.toString()))
                .andExpect(jsonPath("$.googleLinked").value(false))
                .andExpect(jsonPath("$.activeSessions").value(1))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void accessReviewShowsWhoGrantedARole() throws Exception {
        UUID target = person(RoleName.CUSTOMER);
        mockMvc.perform(put(USERS + target + "/roles/DISPATCHER").header("Authorization", admin()))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/admin/access-review").header("Authorization", admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.userId == '" + target + "')].grantedBy", hasItem(adminId.toString())));
    }

    @Test
    void theAuditLogIsSearchableExportableAndVerifiable() throws Exception {
        UUID target = person(RoleName.CUSTOMER);
        reasoned(post(USERS + target + "/block"), "Searching test");

        mockMvc.perform(get(AUDIT).param("target", target.toString()).header("Authorization", admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].action").value("user.blocked"))
                .andExpect(jsonPath("$[0].details.reason").value("Searching test"));

        Instant now = Instant.now();
        mockMvc.perform(get(AUDIT + "/export").header("Authorization", admin())
                        .param("from", now.minus(1, ChronoUnit.HOURS).toString())
                        .param("to", now.plus(1, ChronoUnit.HOURS).toString()))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", startsWith("attachment")))
                .andExpect(content().string(startsWith("seq,at,actor_type")));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.audit_log WHERE action = 'audit.exported'"
                + " AND actor_id = ?", Integer.class, adminId.toString())).isEqualTo(1);

        mockMvc.perform(get(AUDIT + "/verify").header("Authorization", admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));
    }

    @Test
    void badAuditFiltersAre400() throws Exception {
        mockMvc.perform(get(AUDIT).param("actor", "x' OR '1'='1").header("Authorization", admin()))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get(AUDIT).param("count", "1000").header("Authorization", admin()))
                .andExpect(status().isBadRequest());
    }

    private ResultActions reasoned(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
                                   String reason) throws Exception {
        return mockMvc.perform(request.header("Authorization", admin()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"reason\":\"" + reason + "\"}"));
    }

    private String admin() {
        return "Bearer " + issuer.issue(adminId, TestPeople.SOMEONE, List.of("ADMIN"), ADMIN_PERMISSIONS).value();
    }

    private UUID person(RoleName role) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("adm-" + UUID.randomUUID().toString().substring(0, 8)
                    + "@example.com"), "{argon2}$argon2id$irrelevant");
            user.markEmailVerified();
            user.addRole(roles.findByName(role).orElseThrow());
            return users.saveAndFlush(user).getId();
        });
    }

    // One live session (refresh token), the kind a block must end
    private void openSession(UUID userId) {
        Instant now = Instant.now();
        jdbc.update("INSERT INTO identity.refresh_tokens (id, user_id, family_id, token_hash, created_at, expires_at,"
                        + " family_expires_at) VALUES (gen_random_uuid(), ?, gen_random_uuid(), ?, ?, ?, ?)",
                userId, java.util.HexFormat.of().formatHex(java.nio.ByteBuffer.allocate(32).putLong(UUID.randomUUID().getMostSignificantBits()).putLong(UUID.randomUUID().getLeastSignificantBits()).array()), Timestamp.from(now), Timestamp.from(now.plus(1, ChronoUnit.DAYS)),
                Timestamp.from(now.plus(7, ChronoUnit.DAYS)));
    }

    private String statusOf(UUID userId) {
        return jdbc.queryForObject("SELECT status FROM identity.users WHERE id = ?", String.class, userId);
    }

    private List<String> eventTypes(UUID userId) {
        return jdbc.queryForList("SELECT event_type FROM identity.identity_events WHERE user_id = ?", String.class,
                userId);
    }

    private Map<String, Object> lastAudit(UUID userId) {
        return jdbc.queryForMap("SELECT * FROM identity.audit_log WHERE target_id = ? ORDER BY seq DESC LIMIT 1",
                userId.toString());
    }
}
