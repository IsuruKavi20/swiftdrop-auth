package com.swiftdrop.auth.account;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PersonName;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 3d: a copy of everything the auth service holds about me (GDPR Art. 15/20, Sri Lanka PDPA). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PersonalDataExportIT {

    private static final String EXPORT = "/api/v1/me/export";
    private static final String PASSWORD = "my parcel arrives on tuesday";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void containsMyDataFromEveryPartOfTheService() throws Exception {
        String email = uniqueEmail();
        UUID id = namedUser(email, "Nimal Perera");
        jdbc.update("INSERT INTO identity.oauth_accounts (id, user_id, provider, provider_user_id, created_at)"
                + " VALUES (gen_random_uuid(), ?, 'google', ?, now())", id, "google-sub-" + id);
        login(email);
        jdbc.update("INSERT INTO identity.email_change_requests (user_id, old_email, new_email, confirm_expires_at)"
                + " VALUES (?, ?, ?, now() + interval '1 hour')", id, email, "next-" + email);

        export(id).andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("attachment")))
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.subject").value(id.toString()))
                .andExpect(jsonPath("$.exported_at").exists())
                .andExpect(jsonPath("$.sections.account.email").value(email))
                .andExpect(jsonPath("$.sections.account.name").value("Nimal Perera"))
                .andExpect(jsonPath("$.sections.account.email_verified").value(true))
                .andExpect(jsonPath("$.sections.linked_logins[0].provider").value("google"))
                .andExpect(jsonPath("$.sections.sessions", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$.sections.email_changes[0].new_email").value("next-" + email));
    }

    @Test
    void neverContainsSecrets() throws Exception {
        String email = uniqueEmail();
        UUID id = namedUser(email, "Nimal Perera");
        login(email);

        String body = export(id).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain("argon2", "password_hash", "token_hash", "secret")
                .doesNotContainPattern("[0-9a-f]{64}");   // no SHA-256 token hashes of any kind
    }

    @Test
    void containsOnlyMyData() throws Exception {
        String someoneElse = uniqueEmail();
        namedUser(someoneElse, "Kasun Silva");
        UUID me = namedUser(uniqueEmail(), "Nimal Perera");

        String body = export(me).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain(someoneElse, "Kasun");
    }

    @Test
    void aMerchantMachineTokenHasNoPersonalData() throws Exception {
        String machine = "Bearer " + issuer.issueForClient("swiftdrop-web", UUID.randomUUID(), List.of("MERCHANT"),
                List.of("parcel:create")).value();

        mockMvc.perform(get(EXPORT).header("Authorization", machine)).andExpect(status().isForbidden());
        mockMvc.perform(get(EXPORT)).andExpect(status().isUnauthorized());
    }

    // ---- helpers ----

    private ResultActions export(UUID userId) throws Exception {
        String access = issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
        return mockMvc.perform(get(EXPORT).header("Authorization", "Bearer " + access));
    }

    private void login(String email) throws Exception {
        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk());
    }

    private UUID namedUser(String email, String name) {
        String hash = encoder.encode(PASSWORD);
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), hash);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of(name)), Instant.now());
            return users.saveAndFlush(user).getId();
        });
    }

    private static String uniqueEmail() {
        return "export-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
