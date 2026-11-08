package com.swiftdrop.auth.applications;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PersonName;
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

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 7b: deciding role applications (least privilege, no self-approval, re-checks at decision time). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RoleApplicationDecisionIT {

    private static final String QUEUE = "/api/v1/admin/role-applications";
    private static final List<String> DISPATCHER_PERMISSIONS = List.of("parcel:read-all", "parcel:assign",
            "delivery:read-all", "role:approve-courier");
    private static final List<String> ADMIN_PERMISSIONS = List.of("user:read", "user:manage-roles",
            "role:approve-courier", "role:approve-dispatcher");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private RoleRepository roles;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void aDispatcherApprovesACourierAndTheRoleIsGiven() throws Exception {
        UUID applicant = person("Kasun Silva", RoleName.CUSTOMER);
        UUID application = applyFor(applicant, "COURIER");
        UUID saman = person("Saman Perera", RoleName.DISPATCHER);

        decide(dispatcher(saman), application, "{\"decision\":\"APPROVE\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("APPROVED"));

        assertThat(roleNames(applicant)).contains("COURIER");
        assertThat(jdbc.queryForObject("SELECT decided_by FROM identity.role_applications WHERE id = ?", UUID.class,
                application)).isEqualTo(saman);
        assertThat(jdbc.queryForObject("SELECT event_type FROM identity.identity_events WHERE user_id = ?"
                + " ORDER BY seq DESC LIMIT 1", String.class, applicant)).endsWith("roles-changed");
    }

    @Test
    void aDispatcherNeitherSeesNorDecidesDispatcherApplications() throws Exception {
        UUID application = applyFor(person("Nimal Perera", RoleName.CUSTOMER), "DISPATCHER");
        String saman = dispatcher(person("Saman Perera", RoleName.DISPATCHER));

        mockMvc.perform(get(QUEUE).header("Authorization", saman))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].id", not(hasItem(application.toString()))));
        decide(saman, application, "{\"decision\":\"APPROVE\"}").andExpect(status().isForbidden());
        mockMvc.perform(get(QUEUE).param("role", "DISPATCHER").header("Authorization", saman))
                .andExpect(status().isForbidden());
    }

    @Test
    void anAdminApprovesADispatcher() throws Exception {
        UUID applicant = person("Nimal Perera", RoleName.CUSTOMER);
        UUID application = applyFor(applicant, "DISPATCHER");

        decide(admin(person("Ruwan Admin", RoleName.ADMIN)), application, "{\"decision\":\"APPROVE\"}")
                .andExpect(status().isOk());

        assertThat(roleNames(applicant)).contains("DISPATCHER");
    }

    @Test
    void nobodyApprovesTheirOwnApplicationEvenThroughTheApi() throws Exception {
        UUID ruwan = person("Ruwan Admin", RoleName.ADMIN);
        UUID ownApplication = applyFor(ruwan, "COURIER");

        // The CVE-2026-15641 attack: call the decision endpoint directly with your own application
        decide(admin(ruwan), ownApplication, "{\"decision\":\"APPROVE\"}")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ROLE_SELF_DECISION"));

        assertThat(statusOf(ownApplication)).isEqualTo("PENDING");
        assertThat(roleNames(ruwan)).doesNotContain("COURIER");
    }

    @Test
    void aRejectionWithAReasonIsShownToTheApplicant() throws Exception {
        UUID applicant = person("Kasun Silva", RoleName.CUSTOMER);
        UUID application = applyFor(applicant, "COURIER");

        decide(admin(person("Ruwan Admin", RoleName.ADMIN)), application,
                "{\"decision\":\"REJECT\",\"reason\":\"Please add your driving licence in the courier page\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REJECTED"));

        mockMvc.perform(get("/api/v1/me/role-applications").header("Authorization", user(applicant)))
                .andExpect(jsonPath("$[0].status").value("REJECTED"))
                .andExpect(jsonPath("$[0].decision_reason").value("Please add your driving licence in the courier page"));
        assertThat(roleNames(applicant)).doesNotContain("COURIER");
    }

    @Test
    void aDecidedApplicationCantBeDecidedAgain() throws Exception {
        UUID application = applyFor(person("Kasun Silva", RoleName.CUSTOMER), "COURIER");
        String ruwan = admin(person("Ruwan Admin", RoleName.ADMIN));
        decide(ruwan, application, "{\"decision\":\"REJECT\"}").andExpect(status().isOk());

        decide(ruwan, application, "{\"decision\":\"APPROVE\"}").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ROLE_APPLICATION_CLOSED"));
    }

    @Test
    void approvalRechecksTheApplicantAtThatMoment() throws Exception {
        UUID blocked = person("Kasun Silva", RoleName.CUSTOMER);
        UUID blockedApplication = applyFor(blocked, "COURIER");
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE id = ?", blocked);
        UUID nowDispatcher = person("Nimal Perera", RoleName.CUSTOMER);
        UUID conflicting = applyFor(nowDispatcher, "COURIER");
        jdbc.update("INSERT INTO identity.user_roles (user_id, role_id) SELECT ?, id FROM identity.roles"
                + " WHERE name = 'DISPATCHER'", nowDispatcher);
        String ruwan = admin(person("Ruwan Admin", RoleName.ADMIN));

        decide(ruwan, blockedApplication, "{\"decision\":\"APPROVE\"}").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ACCOUNT_NOT_ELIGIBLE"));
        decide(ruwan, conflicting, "{\"decision\":\"APPROVE\"}").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ROLE_CONFLICT"));

        assertThat(statusOf(blockedApplication)).isEqualTo("PENDING");
        assertThat(statusOf(conflicting)).isEqualTo("PENDING");
    }

    @Test
    void theQueueShowsOpenApplicationsWithTheApplicantsName() throws Exception {
        UUID application = applyFor(person("Kasun Silva", RoleName.CUSTOMER), "COURIER");

        mockMvc.perform(get(QUEUE).param("role", "COURIER").header("Authorization", admin(
                        person("Ruwan Admin", RoleName.ADMIN))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + application + "')].applicant.name").value(hasItem("Kasun Silva")))
                .andExpect(jsonPath("$[?(@.id == '" + application + "')].status").value(hasItem("PENDING")));
    }

    @Test
    void peopleWithoutAnApprovePermissionGetNothing() throws Exception {
        UUID application = applyFor(person("Kasun Silva", RoleName.CUSTOMER), "COURIER");
        String customer = user(person("Nimal Perera", RoleName.CUSTOMER));

        mockMvc.perform(get(QUEUE).header("Authorization", customer)).andExpect(status().isForbidden());
        decide(customer, application, "{\"decision\":\"APPROVE\"}").andExpect(status().isForbidden());
    }

    @Test
    void aDecisionThatCommittedWhileAnotherWaitedIsNeverOverwritten() throws Exception {
        UUID applicant = person("Kasun Silva", RoleName.CUSTOMER);
        UUID application = applyFor(applicant, "COURIER");
        String ruwan = admin(person("Ruwan Admin", RoleName.ADMIN));
        java.util.concurrent.CountDownLatch approvedInside = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService approvers = java.util.concurrent.Executors.newFixedThreadPool(2);
        // Approver A: holds the applicant's lock and has already decided "approved", not yet committed
        java.util.concurrent.Future<?> first = approvers.submit(() -> transactions.executeWithoutResult(status -> {
            jdbc.queryForObject("SELECT id FROM identity.users WHERE id = ? FOR UPDATE", UUID.class, applicant);
            jdbc.update("UPDATE identity.role_applications SET status = 'APPROVED', decided_at = now(),"
                    + " decided_by = gen_random_uuid() WHERE id = ?", application);
            approvedInside.countDown();
            try {
                release.await(10, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }));
        assertThat(approvedInside.await(10, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        // Approver B: rejects through the real API; it has to wait for A
        java.util.concurrent.Future<ResultActions> second = approvers.submit(() ->
                decide(ruwan, application, "{\"decision\":\"REJECT\"}"));
        Thread.sleep(500);

        release.countDown();
        first.get(10, java.util.concurrent.TimeUnit.SECONDS);

        second.get(10, java.util.concurrent.TimeUnit.SECONDS).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ROLE_APPLICATION_CLOSED"));
        approvers.shutdown();
        assertThat(statusOf(application)).as("A's decision stands").isEqualTo("APPROVED");
    }

    @Test
    void anApproverWhoLostTheRoleCanNoLongerDecideEvenWithAStillValidToken() throws Exception {
        UUID application = applyFor(person("Kasun Silva", RoleName.CUSTOMER), "COURIER");
        UUID saman = person("Saman Perera", RoleName.DISPATCHER);
        String samansToken = dispatcher(saman);   // issued while Saman was a dispatcher
        jdbc.update("DELETE FROM identity.user_roles WHERE user_id = ?", saman);   // ...then the role was removed

        decide(samansToken, application, "{\"decision\":\"APPROVE\"}").andExpect(status().isForbidden());

        assertThat(statusOf(application)).isEqualTo("PENDING");
    }

    @Test
    void theQueueIsLimitedInSize() throws Exception {
        mockMvc.perform(get(QUEUE).param("count", "101").header("Authorization", admin(
                person("Ruwan Admin", RoleName.ADMIN)))).andExpect(status().isBadRequest());
    }

    // ---- helpers ----

    private UUID applyFor(UUID userId, String role) throws Exception {
        String body = mockMvc.perform(post("/api/v1/me/role-applications").header("Authorization", user(userId))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"" + role + "\"}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return UUID.fromString(JsonPath.read(body, "$.id"));
    }

    private ResultActions decide(String bearer, UUID application, String json) throws Exception {
        return mockMvc.perform(post(QUEUE + "/" + application + "/decision").header("Authorization", bearer)
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private String user(UUID id) {
        return "Bearer " + issuer.issue(id, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
    }

    private String dispatcher(UUID id) {
        return "Bearer " + issuer.issue(id, TestPeople.SOMEONE, List.of("DISPATCHER"), DISPATCHER_PERMISSIONS).value();
    }

    private String admin(UUID id) {
        return "Bearer " + issuer.issue(id, TestPeople.SOMEONE, List.of("ADMIN"), ADMIN_PERMISSIONS).value();
    }

    private String statusOf(UUID application) {
        return jdbc.queryForObject("SELECT status FROM identity.role_applications WHERE id = ?", String.class,
                application);
    }

    private List<String> roleNames(UUID userId) {
        return jdbc.queryForList("SELECT r.name FROM identity.user_roles ur JOIN identity.roles r ON r.id = ur.role_id"
                + " WHERE ur.user_id = ?", String.class, userId);
    }

    private UUID person(String name, RoleName role) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("decide-" + UUID.randomUUID() + "@example.com"), null);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of(name)), Instant.now());
            user.addRole(roles.findByName(role).orElseThrow());
            return users.saveAndFlush(user).getId();
        });
    }
}
