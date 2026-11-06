package com.swiftdrop.auth.user.api;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PersonName;
import com.swiftdrop.auth.user.ProfileSource;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 3a: the logged-in user reads and edits their own identity profile. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ProfileApiIT {

    private static final String PROFILE = "/api/v1/me/profile";
    private static final String MERGE_PATCH = "application/merge-patch+json";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbc;

    @Test
    void readsMyProfileWithStandardClaimNamesAndAnEtag() throws Exception {
        UUID id = userNamed("Nimal Perera");

        read(id).andExpect(status().isOk())
                .andExpect(header().exists("ETag"))
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.sub").value(id.toString()))
                .andExpect(jsonPath("$.name").value("Nimal Perera"))
                .andExpect(jsonPath("$.email_verified").value(true))
                .andExpect(jsonPath("$.updated_at").isNumber());
    }

    @Test
    void changesTheNameAndBecomesTheUsersOwnProfile() throws Exception {
        UUID id = userNamed("Nimal Perera");
        String etag = etagOf(id);

        edit(id, etag, "{\"name\":\"Nimal K. Perera\",\"locale\":\"si-LK\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Nimal K. Perera"))
                .andExpect(jsonPath("$.locale").value("si-LK"))
                .andExpect(header().string("ETag", not(etag)));

        User user = users.findById(id).orElseThrow();
        assertThat(user.getName()).isEqualTo("Nimal K. Perera");
        assertThat(user.getProfileSource()).isEqualTo(ProfileSource.USER);
    }

    @Test
    void nullRemovesAFieldAndMissingFieldsStayAsTheyAre() throws Exception {
        UUID id = userNamed("Nimal Perera");
        edit(id, etagOf(id), "{\"given_name\":\"Nimal\",\"family_name\":\"Perera\"}").andExpect(status().isOk());

        edit(id, etagOf(id), "{\"given_name\":null}").andExpect(status().isOk());

        User user = users.findById(id).orElseThrow();
        assertThat(user.getGivenName()).isNull();
        assertThat(user.getFamilyName()).isEqualTo("Perera");
        assertThat(user.getName()).isEqualTo("Nimal Perera");
    }

    @Test
    void anEditWithoutIfMatchIsRefused() throws Exception {
        UUID id = userNamed("Nimal Perera");

        mockMvc.perform(patch(PROFILE).header("Authorization", bearer(id)).contentType(MERGE_PATCH)
                        .content("{\"name\":\"Someone Else\"}"))
                .andExpect(status().isPreconditionRequired())
                .andExpect(jsonPath("$.code").value("PRECONDITION_REQUIRED"));
    }

    @Test
    void anEditBasedOnAnOldReadIsRefusedInsteadOfOverwriting() throws Exception {
        UUID id = userNamed("Nimal Perera");
        String phoneSaw = etagOf(id);
        edit(id, etagOf(id), "{\"name\":\"Changed On Laptop\"}").andExpect(status().isOk());

        edit(id, phoneSaw, "{\"name\":\"Changed On Phone\"}")
                .andExpect(status().isPreconditionFailed())
                .andExpect(jsonPath("$.code").value("PRECONDITION_FAILED"));

        assertThat(users.findById(id).orElseThrow().getName()).isEqualTo("Changed On Laptop");
    }

    @Test
    void theNameCanBeChangedButNotRemoved() throws Exception {
        UUID id = userNamed("Nimal Perera");

        edit(id, etagOf(id), "{\"name\":null}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_NAME"));
    }

    @Test
    void badValuesAreRefusedWithoutEchoingThem() throws Exception {
        UUID id = userNamed("Nimal Perera");

        edit(id, etagOf(id), "{\"name\":\"Evil\\u202Ename\"}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_NAME"))
                .andExpect(content().string(not(containsString("Evil"))));
        edit(id, etagOf(id), "{\"picture\":\"http://tracker.example/pixel.png\"}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_PROFILE"))
                .andExpect(content().string(not(containsString("tracker"))));
        edit(id, etagOf(id), "{\"locale\":\"<script>\"}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_PROFILE"));
    }

    @Test
    void aPhotoMayOnlyComeFromATrustedImageHost() throws Exception {
        UUID id = userNamed("Nimal Perera");

        edit(id, etagOf(id), "{\"picture\":\"https://tracker.example/pixel.png\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_PROFILE"))
                .andExpect(jsonPath("$.errors[0].rule").value("TrustedHost"));
        edit(id, etagOf(id), "{\"picture\":\"https://lh3.googleusercontent.com/a/photo\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.picture").value("https://lh3.googleusercontent.com/a/photo"));
    }

    @Test
    void onlyProfileFieldsCanBeEdited() throws Exception {
        UUID id = userNamed("Nimal Perera");

        edit(id, etagOf(id), "{\"email\":\"attacker@example.com\"}").andExpect(status().isBadRequest());
        edit(id, etagOf(id), "{\"roles\":[\"ADMIN\"]}").andExpect(status().isBadRequest());
        edit(id, etagOf(id), "{\"name\":42}").andExpect(status().isBadRequest());

        assertThat(users.findWithRolesById(id).orElseThrow().roleNames()).as("roles untouched").isEmpty();
    }

    @Test
    void aDisabledOrDeletedAccountsStillValidTokenCanNeitherReadNorEdit() throws Exception {
        UUID id = userNamed("Nimal Perera");
        String etag = etagOf(id);
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE id = ?", id);

        read(id).andExpect(status().isUnauthorized());
        edit(id, etag, "{\"name\":\"Back From The Dead\"}").andExpect(status().isUnauthorized());

        assertThat(users.findById(id).orElseThrow().getName()).isEqualTo("Nimal Perera");
    }

    @Test
    void aMerchantMachineTokenHasNoProfile() throws Exception {
        String machine = "Bearer " + issuer.issueForClient("swiftdrop-web", UUID.randomUUID(), List.of("MERCHANT"),
                List.of("parcel:create")).value();

        mockMvc.perform(get(PROFILE).header("Authorization", machine)).andExpect(status().isForbidden());
    }

    @Test
    void withoutATokenThereIsNoProfile() throws Exception {
        mockMvc.perform(get(PROFILE)).andExpect(status().isUnauthorized());
    }

    // ---- helpers ----

    private UUID userNamed(String name) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("profile-" + UUID.randomUUID() + "@example.com"), null);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of(name)), Instant.now());
            return users.saveAndFlush(user).getId();
        });
    }

    private String bearer(UUID userId) {
        return "Bearer " + issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
    }

    private ResultActions read(UUID userId) throws Exception {
        return mockMvc.perform(get(PROFILE).header("Authorization", bearer(userId)));
    }

    private String etagOf(UUID userId) throws Exception {
        MvcResult result = read(userId).andExpect(status().isOk()).andReturn();
        return result.getResponse().getHeader("ETag");
    }

    private ResultActions edit(UUID userId, String etag, String json) throws Exception {
        return mockMvc.perform(patch(PROFILE).header("Authorization", bearer(userId)).header("If-Match", etag)
                .contentType(MERGE_PATCH).content(json));
    }
}
