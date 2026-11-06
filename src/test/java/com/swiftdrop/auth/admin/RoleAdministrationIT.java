package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Real database, real tokens: permissions are seeded, admins manage roles, the rules hold. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RoleAdministrationIT {

    private static final String ADMIN_USERS = "/api/v1/admin/users";

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

    @Test
    void everyRoleHasItsSeededPermissions() {
        List<String> dispatcher = jdbc.queryForList("""
                SELECT p.name FROM identity.permissions p
                JOIN identity.role_permissions rp ON rp.permission_id = p.id
                JOIN identity.roles r ON r.id = rp.role_id WHERE r.name = 'DISPATCHER'""", String.class);

        assertThat(dispatcher).containsExactlyInAnyOrder("parcel:read-all", "parcel:assign", "delivery:read-all");
    }

    @Test
    void adminGrantsCourierRoleAndTheNextTokenCarriesIt() throws Exception {
        UUID target = customer();

        mockMvc.perform(put(ADMIN_USERS + "/" + target + "/roles/COURIER").header("Authorization", admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").value(org.hamcrest.Matchers.containsInAnyOrder("CUSTOMER", "COURIER")));

        assertThat(roleNamesOf(target)).contains("COURIER");
    }

    @Test
    void grantingTwiceChangesNothing() throws Exception {
        UUID target = customer();
        mockMvc.perform(put(ADMIN_USERS + "/" + target + "/roles/COURIER").header("Authorization", admin()));

        mockMvc.perform(put(ADMIN_USERS + "/" + target + "/roles/COURIER").header("Authorization", admin()))
                .andExpect(status().isOk());

        assertThat(roleNamesOf(target)).containsExactlyInAnyOrder("CUSTOMER", "COURIER");
    }

    @Test
    void adminRevokesARole() throws Exception {
        UUID target = customer();
        mockMvc.perform(put(ADMIN_USERS + "/" + target + "/roles/COURIER").header("Authorization", admin()));

        mockMvc.perform(delete(ADMIN_USERS + "/" + target + "/roles/COURIER").header("Authorization", admin()))
                .andExpect(status().isOk());

        assertThat(roleNamesOf(target)).containsExactly("CUSTOMER");
    }

    @Test
    void nonAdminCannotManageRoles() throws Exception {
        UUID target = customer();
        String courierToken = "Bearer " + issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("COURIER"),
                List.of("delivery:read-own", "delivery:update-status")).value();

        mockMvc.perform(put(ADMIN_USERS + "/" + target + "/roles/ADMIN").header("Authorization", courierToken))
                .andExpect(status().isForbidden());
        assertThat(roleNamesOf(target)).containsExactly("CUSTOMER");
    }

    @Test
    void adminCannotRemoveTheirOwnAdminRole() throws Exception {
        UUID adminId = customer();
        transactions.executeWithoutResult(status -> users.findById(adminId).orElseThrow()
                .addRole(roles.findByName(RoleName.ADMIN).orElseThrow()));
        String ownToken = "Bearer " + issuer.issue(adminId, TestPeople.SOMEONE, List.of("ADMIN"), List.of("user:read", "user:manage-roles")).value();

        mockMvc.perform(delete(ADMIN_USERS + "/" + adminId + "/roles/ADMIN").header("Authorization", ownToken))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("CANNOT_REMOVE_OWN_ADMIN"));
    }

    @Test
    void merchantRoleIsOnlyGivenThroughMerchantApproval() throws Exception {
        mockMvc.perform(put(ADMIN_USERS + "/" + customer() + "/roles/MERCHANT").header("Authorization", admin()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("ROLE_NOT_ASSIGNABLE"));
    }

    @Test
    void userMustKeepAtLeastOneRole() throws Exception {
        mockMvc.perform(delete(ADMIN_USERS + "/" + customer() + "/roles/CUSTOMER").header("Authorization", admin()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("LAST_ROLE"));
    }

    @Test
    void rolesAreOnlyGrantedToVerifiedAccounts() throws Exception {
        UUID unverified = customer("unv-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com", false);

        mockMvc.perform(put(ADMIN_USERS + "/" + unverified + "/roles/ADMIN").header("Authorization", admin()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ACCOUNT_NOT_ELIGIBLE"));
        assertThat(roleNamesOf(unverified)).containsExactly("CUSTOMER");
    }

    @Test
    void theLastAdminCannotBeRemoved() throws Exception {
        jdbc.update("DELETE FROM identity.user_roles WHERE role_id = (SELECT id FROM identity.roles WHERE name = 'ADMIN')");
        UUID onlyAdmin = customer();
        mockMvc.perform(put(ADMIN_USERS + "/" + onlyAdmin + "/roles/ADMIN").header("Authorization", admin()))
                .andExpect(status().isOk());

        mockMvc.perform(delete(ADMIN_USERS + "/" + onlyAdmin + "/roles/ADMIN").header("Authorization", admin()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("LAST_ADMIN"));
        assertThat(roleNamesOf(onlyAdmin)).contains("ADMIN");
    }

    @Test
    void unknownUserIs404() throws Exception {
        mockMvc.perform(put(ADMIN_USERS + "/" + UUID.randomUUID() + "/roles/COURIER").header("Authorization", admin()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
    }

    @Test
    void adminFindsAUserByEmail() throws Exception {
        String email = "find-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        UUID id = customer(email);

        mockMvc.perform(get(ADMIN_USERS).param("email", email.toUpperCase()).header("Authorization", admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    private String admin() {
        return "Bearer " + issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("ADMIN"),
                List.of("user:read", "user:manage-roles")).value();
    }

    private UUID customer() {
        return customer("role-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com");
    }

    private UUID customer(String email) {
        return customer(email, true);
    }

    private UUID customer(String email, boolean verified) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), "{argon2}$argon2id$irrelevant");
            if (verified) {
                user.markEmailVerified();
            }
            Role customer = roles.findByName(RoleName.CUSTOMER).orElseThrow();
            user.addRole(customer);
            return users.saveAndFlush(user).getId();
        });
    }

    private List<String> roleNamesOf(UUID userId) {
        return jdbc.queryForList("""
                SELECT r.name FROM identity.roles r JOIN identity.user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = ?""", String.class, userId);
    }
}
