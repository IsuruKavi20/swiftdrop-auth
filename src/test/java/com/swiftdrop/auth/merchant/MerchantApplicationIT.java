package com.swiftdrop.auth.merchant;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.token.AccessTokenIssuer;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Merchant registration and admin approval (deep dive 25), real database, real tokens. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class MerchantApplicationIT {

    private static final String APPLICATION = "/api/v1/merchants/application";
    private static final String ADMIN = "/api/v1/admin/merchants";
    private static final List<String> ADMIN_PERMISSIONS = List.of("merchant:approve", "user:read", "user:manage-roles");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private UserRepository users;

    @Autowired
    private RoleRepository roles;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void aVerifiedUserAppliesAndTheApplicationIsPending() throws Exception {
        UUID nimal = verifiedCustomer();

        apply(nimal).andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andExpect(jsonPath("$.businessName").value("Nimal Stores"));

        mockMvc.perform(get(APPLICATION).header("Authorization", customerToken(nimal)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PENDING"));
    }

    @Test
    void oneOpenApplicationPerUser() throws Exception {
        UUID nimal = verifiedCustomer();
        apply(nimal).andExpect(status().isCreated());

        apply(nimal).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MERCHANT_APPLICATION_EXISTS"));
    }

    @Test
    void invalidApplicationDataIsRejected() throws Exception {
        mockMvc.perform(post(APPLICATION).header("Authorization", customerToken(verifiedCustomer()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"businessName\":\"\",\"registrationNumber\":\"PV-1\",\"website\":\"javascript:alert(1)\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    @Test
    void applyingNeedsALoggedInUser() throws Exception {
        mockMvc.perform(post(APPLICATION).contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminSeesPendingApplicationsButOthersCannot() throws Exception {
        UUID nimal = verifiedCustomer();
        apply(nimal);

        MvcResult list = mockMvc.perform(get(ADMIN).param("status", "PENDING").header("Authorization", adminToken()))
                .andExpect(status().isOk()).andReturn();
        List<String> userIds = JsonPath.read(list.getResponse().getContentAsString(), "$[*].userId");
        assertThat(userIds).contains(nimal.toString());

        mockMvc.perform(get(ADMIN).param("status", "PENDING").header("Authorization", customerToken(nimal)))
                .andExpect(status().isForbidden());
    }

    @Test
    void approvalMakesTheUserAMerchant() throws Exception {
        UUID nimal = verifiedCustomer();
        String merchantId = idOf(apply(nimal));

        decide(merchantId, "APPROVE", null, adminToken()).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("APPROVED"));

        assertThat(roleNamesOf(nimal)).containsExactlyInAnyOrder("CUSTOMER", "MERCHANT");
    }

    @Test
    void aDecisionIsFinal() throws Exception {
        String merchantId = idOf(apply(verifiedCustomer()));
        decide(merchantId, "APPROVE", null, adminToken()).andExpect(status().isOk());

        decide(merchantId, "REJECT", "NOT_ELIGIBLE", adminToken()).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MERCHANT_ALREADY_DECIDED"));
    }

    @Test
    void twoAdminsDecidingAtTheSameMomentCannotBothWin() throws Exception {
        String merchantId = idOf(apply(verifiedCustomer()));
        String admin = adminToken();
        CountDownLatch start = new CountDownLatch(1);
        List<Integer> statuses = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Future<?>> runs = new ArrayList<>();
            for (String decision : List.of("APPROVE", "REJECT")) {
                runs.add(pool.submit(() -> {
                    start.await();
                    String reason = "REJECT".equals(decision) ? "NOT_ELIGIBLE" : null;
                    statuses.add(decide(merchantId, decision, reason, admin).andReturn().getResponse().getStatus());
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

        assertThat(statuses).containsExactlyInAnyOrder(200, 409);
    }

    @Test
    void anAdminCannotApproveTheirOwnApplication() throws Exception {
        UUID admin = verifiedCustomer();
        String merchantId = idOf(apply(admin));
        String ownAdminToken = "Bearer " + issuer.issue(admin, TestPeople.SOMEONE, List.of("ADMIN"), ADMIN_PERMISSIONS).value();

        decide(merchantId, "APPROVE", null, ownAdminToken).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("CANNOT_DECIDE_OWN_APPLICATION"));
    }

    @Test
    void aRejectionNeedsAReasonAndAllowsReapplyingAfterSevenDays() throws Exception {
        UUID nimal = verifiedCustomer();
        String merchantId = idOf(apply(nimal));
        decide(merchantId, "REJECT", null, adminToken()).andExpect(status().isBadRequest());

        decide(merchantId, "REJECT", "INCOMPLETE_INFORMATION", adminToken()).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REJECTED"))
                .andExpect(jsonPath("$.decisionReason").value("INCOMPLETE_INFORMATION"));
        assertThat(roleNamesOf(nimal)).containsExactly("CUSTOMER");

        apply(nimal).andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("MERCHANT_REAPPLY_TOO_SOON"));

        jdbc.update("UPDATE identity.merchants SET decided_at = now() - interval '8 days' WHERE id = ?::uuid", merchantId);
        apply(nimal).andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("PENDING"));
    }

    @Test
    void suspendingAMerchantRemovesTheRoleAndReinstatingGivesItBack() throws Exception {
        UUID nimal = verifiedCustomer();
        String merchantId = idOf(apply(nimal));
        decide(merchantId, "APPROVE", null, adminToken());

        changeStatus(merchantId, "SUSPEND").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("SUSPENDED"));
        assertThat(roleNamesOf(nimal)).containsExactly("CUSTOMER");

        changeStatus(merchantId, "SUSPEND").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MERCHANT_INVALID_STATE"));

        changeStatus(merchantId, "REINSTATE").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("APPROVED"));
        assertThat(roleNamesOf(nimal)).containsExactlyInAnyOrder("CUSTOMER", "MERCHANT");
    }

    @Test
    void oneBusinessCanOnlyBeApprovedOnce() throws Exception {
        String registration = "PV-" + UUID.randomUUID().toString().substring(0, 8);
        String first = idOf(apply(verifiedCustomer(), registration));
        String second = idOf(apply(verifiedCustomer(), registration.toLowerCase()));
        decide(first, "APPROVE", null, adminToken()).andExpect(status().isOk());

        decide(second, "APPROVE", null, adminToken()).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MERCHANT_DUPLICATE_BUSINESS"));
    }

    @Test
    void theMerchantRoleCannotBeRemovedThroughTheRoleApi() throws Exception {
        UUID nimal = verifiedCustomer();
        decide(idOf(apply(nimal)), "APPROVE", null, adminToken());

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .delete("/api/v1/admin/users/" + nimal + "/roles/MERCHANT").header("Authorization", adminToken()))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("ROLE_NOT_ASSIGNABLE"));
    }

    @Test
    void unknownApplicationIs404() throws Exception {
        decide(UUID.randomUUID().toString(), "APPROVE", null, adminToken()).andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("MERCHANT_NOT_FOUND"));
    }

    // ---- helpers ----

    private ResultActions apply(UUID userId) throws Exception {
        return apply(userId, "PV-" + UUID.randomUUID().toString().substring(0, 8));
    }

    private ResultActions apply(UUID userId, String registrationNumber) throws Exception {
        return mockMvc.perform(post(APPLICATION).header("Authorization", customerToken(userId))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body().replace("PV-12345", registrationNumber)));
    }

    private ResultActions changeStatus(String merchantId, String change) throws Exception {
        return mockMvc.perform(post(ADMIN + "/" + merchantId + "/status").header("Authorization", adminToken())
                .contentType(MediaType.APPLICATION_JSON).content("{\"change\":\"" + change + "\"}"));
    }

    private static String body() {
        return "{\"businessName\":\"Nimal Stores\",\"registrationNumber\":\"PV-12345\",\"website\":\"https://nimal.example\"}";
    }

    private ResultActions decide(String merchantId, String decision, String reason, String adminToken) throws Exception {
        String json = reason == null ? "{\"decision\":\"" + decision + "\"}"
                : "{\"decision\":\"" + decision + "\",\"reason\":\"" + reason + "\"}";
        return mockMvc.perform(post(ADMIN + "/" + merchantId + "/decision").header("Authorization", adminToken)
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private static String idOf(ResultActions created) throws Exception {
        return JsonPath.read(created.andReturn().getResponse().getContentAsString(), "$.id");
    }

    private String customerToken(UUID userId) {
        return "Bearer " + issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of("parcel:create", "parcel:read-own")).value();
    }

    private String adminToken() {
        return "Bearer " + issuer.issue(verifiedCustomer(), TestPeople.SOMEONE, List.of("ADMIN"), ADMIN_PERMISSIONS).value();
    }

    private UUID verifiedCustomer() {
        String email = "m-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), "{argon2}$argon2id$irrelevant");
            user.addRole(roles.findByName(RoleName.CUSTOMER).orElseThrow());
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });
    }

    private List<String> roleNamesOf(UUID userId) {
        return jdbc.queryForList("""
                SELECT r.name FROM identity.roles r JOIN identity.user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = ?""", String.class, userId);
    }
}
