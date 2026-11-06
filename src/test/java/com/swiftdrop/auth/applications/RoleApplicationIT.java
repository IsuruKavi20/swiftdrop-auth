package com.swiftdrop.auth.applications;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.admin.RoleAdministration;
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

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 7a: applying for the COURIER or DISPATCHER role (and withdrawing), with every rule. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RoleApplicationIT {

    private static final String MINE = "/api/v1/me/role-applications";

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
    private RoleAdministration roleAdministration;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void applyingCreatesAPendingApplication() throws Exception {
        UUID id = person(RoleName.CUSTOMER);

        apply(id, "{\"role\":\"COURIER\",\"note\":\"I have a motorbike and know Kandy well\"}")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.role").value("COURIER"))
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andExpect(jsonPath("$.note").value("I have a motorbike and know Kandy well"));

        mockMvc.perform(get(MINE).header("Authorization", bearer(id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].status").value("PENDING"));
    }

    @Test
    void theNoteIsOptional() throws Exception {
        apply(person(RoleName.CUSTOMER), "{\"role\":\"DISPATCHER\"}").andExpect(status().isCreated());
    }

    @Test
    void onlyCourierAndDispatcherCanBeAppliedFor() throws Exception {
        UUID id = person(RoleName.CUSTOMER);

        apply(id, "{\"role\":\"ADMIN\"}").andExpect(status().isBadRequest());
        apply(id, "{\"role\":\"MERCHANT\"}").andExpect(status().isBadRequest());
        apply(id, "{\"role\":\"WIZARD\"}").andExpect(status().isBadRequest());
    }

    @Test
    void oneOpenApplicationPerRole() throws Exception {
        UUID id = person(RoleName.CUSTOMER);
        apply(id, "{\"role\":\"COURIER\"}").andExpect(status().isCreated());

        apply(id, "{\"role\":\"COURIER\"}").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ROLE_APPLICATION_EXISTS"));
    }

    @Test
    void notForARoleAlreadyHeld() throws Exception {
        apply(person(RoleName.CUSTOMER, RoleName.COURIER), "{\"role\":\"COURIER\"}").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ROLE_ALREADY_HELD"));
    }

    @Test
    void aCourierCannotAlsoBecomeADispatcherAndViceVersa() throws Exception {
        apply(person(RoleName.CUSTOMER, RoleName.COURIER), "{\"role\":\"DISPATCHER\"}")
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("ROLE_CONFLICT"));
        apply(person(RoleName.CUSTOMER, RoleName.DISPATCHER), "{\"role\":\"COURIER\"}")
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("ROLE_CONFLICT"));
    }

    @Test
    void theAdminGrantEndpointFollowsTheSameSeparationOfDuties() {
        UUID dispatcher = person(RoleName.CUSTOMER, RoleName.DISPATCHER);

        assertThatThrownBy(() -> roleAdministration.grant(UUID.randomUUID(), dispatcher, RoleName.COURIER))
                .isInstanceOf(com.swiftdrop.auth.common.error.DomainException.class)
                .extracting(e -> ((com.swiftdrop.auth.common.error.DomainException) e).errorCode())
                .isEqualTo(com.swiftdrop.auth.common.error.ErrorCode.ROLE_CONFLICT);
    }

    @Test
    void afterARejectionTheApplicantWaitsSevenDays() throws Exception {
        UUID id = person(RoleName.CUSTOMER);
        UUID applicationId = idOf(apply(id, "{\"role\":\"COURIER\"}"));
        jdbc.update("UPDATE identity.role_applications SET status = 'REJECTED', decided_at = now(),"
                + " decided_by = gen_random_uuid() WHERE id = ?", applicationId);

        apply(id, "{\"role\":\"COURIER\"}").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ROLE_REAPPLY_TOO_SOON"));

        jdbc.update("UPDATE identity.role_applications SET decided_at = now() - interval '8 days',"
                + " created_at = now() - interval '9 days' WHERE id = ?", applicationId);
        apply(id, "{\"role\":\"COURIER\"}").andExpect(status().isCreated());
    }

    @Test
    void theApplicantCanWithdrawAnOpenApplicationButNotSomeoneElses() throws Exception {
        UUID applicant = person(RoleName.CUSTOMER);
        UUID stranger = person(RoleName.CUSTOMER);
        UUID applicationId = idOf(apply(applicant, "{\"role\":\"COURIER\"}"));

        mockMvc.perform(delete(MINE + "/" + applicationId).header("Authorization", bearer(stranger)))
                .andExpect(status().isNotFound());
        mockMvc.perform(delete(MINE + "/" + applicationId).header("Authorization", bearer(applicant)))
                .andExpect(status().isNoContent());

        assertThat(jdbc.queryForObject("SELECT status FROM identity.role_applications WHERE id = ?", String.class,
                applicationId)).isEqualTo("WITHDRAWN");
        mockMvc.perform(delete(MINE + "/" + applicationId).header("Authorization", bearer(applicant)))
                .andExpect(status().isConflict());
        apply(applicant, "{\"role\":\"COURIER\"}").andExpect(status().isCreated());   // no waiting after a withdrawal
    }

    @Test
    void aLongNoteIsRefused() throws Exception {
        apply(person(RoleName.CUSTOMER), "{\"role\":\"COURIER\",\"note\":\"" + "x".repeat(501) + "\"}")
                .andExpect(status().isBadRequest());
    }

    @Test
    void anInactiveAccountOrAMachineCannotApply() throws Exception {
        UUID disabled = person(RoleName.CUSTOMER);
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE id = ?", disabled);
        String machine = "Bearer " + issuer.issueForClient("swiftdrop-web", UUID.randomUUID(), List.of("MERCHANT"),
                List.of("parcel:create")).value();

        apply(disabled, "{\"role\":\"COURIER\"}").andExpect(status().isUnauthorized());
        mockMvc.perform(post(MINE).header("Authorization", machine).contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"COURIER\"}")).andExpect(status().isForbidden());
    }

    // ---- helpers ----

    private ResultActions apply(UUID userId, String json) throws Exception {
        return mockMvc.perform(post(MINE).header("Authorization", bearer(userId))
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private static UUID idOf(ResultActions created) throws Exception {
        return UUID.fromString(JsonPath.read(created.andExpect(status().isCreated()).andReturn().getResponse()
                .getContentAsString(), "$.id"));
    }

    private String bearer(UUID userId) {
        return "Bearer " + issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
    }

    private UUID person(RoleName... held) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("apply-" + UUID.randomUUID() + "@example.com"), null);
            user.markEmailVerified();
            for (RoleName role : held) {
                user.addRole(roles.findByName(role).orElseThrow());
            }
            return users.saveAndFlush(user).getId();
        });
    }
}
