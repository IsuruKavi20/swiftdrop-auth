package com.swiftdrop.auth.applications;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.MailpitClient;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 7c: the applicant is told by email when their application is decided (sent through the outbox). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RoleApplicationEmailIT {

    private static final List<String> ADMIN_PERMISSIONS = List.of("role:approve-courier", "role:approve-dispatcher");

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
    private MailpitClient mailpit;

    @Test
    void anApprovalTellsTheApplicantTheirNewRole() throws Exception {
        String email = uniqueEmail();
        UUID application = applyFor(person(email), "COURIER");

        decide(application, "{\"decision\":\"APPROVE\"}");

        MailpitClient.Mail mail = mailpit.awaitMessageTo(email, ApplicationEmailSubjects.APPROVED);
        assertThat(mail.text()).contains("courier");
    }

    @Test
    void aRejectionTellsTheApplicantWhyAndWhenTheyCanTryAgain() throws Exception {
        String email = uniqueEmail();
        UUID application = applyFor(person(email), "DISPATCHER");

        decide(application, "{\"decision\":\"REJECT\",\"reason\":\"We are not hiring dispatchers this month\"}");

        MailpitClient.Mail mail = mailpit.awaitMessageTo(email, ApplicationEmailSubjects.REJECTED);
        assertThat(mail.text()).contains("We are not hiring dispatchers this month").contains("7 days");
    }

    // ---- helpers ----

    private UUID applyFor(UUID userId, String role) throws Exception {
        String bearer = "Bearer " + issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        String body = mockMvc.perform(post("/api/v1/me/role-applications").header("Authorization", bearer)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"" + role + "\"}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return UUID.fromString(JsonPath.read(body, "$.id"));
    }

    private void decide(UUID application, String json) throws Exception {
        // A real admin: the decision re-checks the approver in the database (a token alone isn't enough)
        UUID adminId = transactions.execute(status -> {
            User admin = new User(EmailAddress.of(uniqueEmail()), null);
            admin.markEmailVerified();
            admin.addRole(roles.findByName(RoleName.ADMIN).orElseThrow());
            return users.saveAndFlush(admin).getId();
        });
        String admin = "Bearer " + issuer.issue(adminId, TestPeople.SOMEONE, List.of("ADMIN"),
                ADMIN_PERMISSIONS).value();
        mockMvc.perform(post("/api/v1/admin/role-applications/" + application + "/decision")
                        .header("Authorization", admin).contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    private UUID person(String email) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), null);
            user.markEmailVerified();
            user.addRole(roles.findByName(RoleName.CUSTOMER).orElseThrow());
            return users.saveAndFlush(user).getId();
        });
    }

    private static String uniqueEmail() {
        return "applied-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
