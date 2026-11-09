package com.swiftdrop.auth.directory;

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
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 5: the Directory API, for SwiftDrop's backend only (service client credentials). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class DirectoryIT {

    // Configured in application-test.yml (only SHA-256 hashes of these secrets are stored there)
    private static final String READER = "svc_swiftdrop-reader";
    private static final String READER_SECRET = "directory-reader-test-secret-0123456789abcdef";
    private static final String MAILER = "svc_swiftdrop-notify";
    private static final String MAILER_SECRET = "directory-mailer-test-secret-0123456789abcdef";
    private static final String USERS = "/api/v1/directory/users";

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
    void aServiceClientLogsInWithClientCredentials() throws Exception {
        mockMvc.perform(post("/oauth2/token").header("Authorization", basic(READER, READER_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=client_credentials"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").doesNotExist());

        mockMvc.perform(post("/oauth2/token").header("Authorization", basic(READER, "wrong secret"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void showsAPersonWithoutEmailToAReader() throws Exception {
        UUID id = person("Kasun Silva", RoleName.COURIER);

        mockMvc.perform(get(USERS + "/" + id).header("Authorization", serviceToken(READER, READER_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.name").value("Kasun Silva"))
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.roles", hasItem("COURIER")))
                .andExpect(jsonPath("$.email").doesNotExist());
    }

    @Test
    void showsTheEmailOnlyWithTheEmailPermission() throws Exception {
        UUID id = person("Kasun Silva", RoleName.COURIER);

        mockMvc.perform(get(USERS + "/" + id).header("Authorization", serviceToken(MAILER, MAILER_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").exists())
                .andExpect(jsonPath("$.email_verified").value(true));

        // Identity step 9a: every email read is audited (which client, how many people; never the addresses)
        assertThat(jdbc.queryForObject("SELECT details FROM identity.audit_log WHERE action = 'directory.email-read'"
                + " AND actor_id = ? ORDER BY seq DESC LIMIT 1", String.class, MAILER)).isEqualTo("{\"people\":1}");
    }

    @Test
    void noUserTokenCanUseTheDirectoryNotEvenAnAdmins() throws Exception {
        UUID id = person("Kasun Silva", RoleName.COURIER);
        String admin = "Bearer " + issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("ADMIN"),
                List.of("user:read", "user:manage-roles")).value();

        mockMvc.perform(get(USERS + "/" + id).header("Authorization", admin)).andExpect(status().isForbidden());
        mockMvc.perform(get(USERS + "/" + id)).andExpect(status().isUnauthorized());
    }

    @Test
    void aDeletedPersonShowsOnlyThatTheyAreGone() throws Exception {
        UUID id = person("Kasun Silva", RoleName.COURIER);
        transactions.executeWithoutResult(status ->
                users.findById(id).orElseThrow().beginDeletion(Instant.now()));

        mockMvc.perform(get(USERS + "/" + id).header("Authorization", serviceToken(MAILER, MAILER_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DELETED"))
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.name").doesNotExist())
                .andExpect(jsonPath("$.email").doesNotExist());
    }

    @Test
    void anUnknownIdIsNotFound() throws Exception {
        mockMvc.perform(get(USERS + "/" + UUID.randomUUID()).header("Authorization", serviceToken(READER, READER_SECRET)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
    }

    @Test
    void looksUpManyPeopleAtOnceAndSkipsUnknownIds() throws Exception {
        UUID first = person("Kasun Silva", RoleName.COURIER);
        UUID second = person("Nimal Perera", RoleName.CUSTOMER);

        mockMvc.perform(post(USERS + "/lookup").header("Authorization", serviceToken(READER, READER_SECRET))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ids\":[\"" + first + "\",\"" + second + "\",\"" + UUID.randomUUID() + "\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.Resources", hasSize(2)));
    }

    @Test
    void aLookupIsLimitedTo100Ids() throws Exception {
        String ids = IntStream.range(0, 101).mapToObj(i -> "\"" + UUID.randomUUID() + "\"")
                .collect(Collectors.joining(","));

        mockMvc.perform(post(USERS + "/lookup").header("Authorization", serviceToken(READER, READER_SECRET))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"ids\":[" + ids + "]}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listsPeopleByRoleAndStatusInPages() throws Exception {
        person("Courier One", RoleName.COURIER);
        person("Courier Two", RoleName.COURIER);
        person("Courier Three", RoleName.COURIER);

        mockMvc.perform(get(USERS).param("role", "COURIER").param("status", "ACTIVE")
                        .param("startIndex", "1").param("count", "2")
                        .header("Authorization", serviceToken(READER, READER_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults", greaterThanOrEqualTo(3)))
                .andExpect(jsonPath("$.startIndex").value(1))
                .andExpect(jsonPath("$.itemsPerPage", lessThanOrEqualTo(2)))
                .andExpect(jsonPath("$.Resources", hasSize(2)))
                .andExpect(jsonPath("$.Resources[0].roles", hasItem("COURIER")));
    }

    @Test
    void deletedPeopleCannotBeListedAndHugeOffsetsAreRefused() throws Exception {
        mockMvc.perform(get(USERS).param("status", "DELETED").header("Authorization", serviceToken(READER, READER_SECRET)))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get(USERS).param("startIndex", "10001").header("Authorization", serviceToken(READER, READER_SECRET)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void onlyOurServiceClientsCanEverHoldDirectoryAccess() throws Exception {
        UUID id = person("Kasun Silva", RoleName.COURIER);
        // No database role grants directory:* (seed data can never hand it to users)
        org.assertj.core.api.Assertions.assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM identity.permissions WHERE name LIKE 'directory:%'", Integer.class)).isZero();
        // Defence in depth: even a user-app token that somehow carried directory:read is refused
        String forged = "Bearer " + issuer.issue(UUID.randomUUID(), TestPeople.SOMEONE, List.of("CUSTOMER"),
                List.of("directory:read", "directory:read-email")).value();

        mockMvc.perform(get(USERS + "/" + id).header("Authorization", forged)).andExpect(status().isForbidden());
    }

    @Test
    void pagesAreAtMost100() throws Exception {
        mockMvc.perform(get(USERS).param("count", "101").header("Authorization", serviceToken(READER, READER_SECRET)))
                .andExpect(status().isBadRequest());
    }

    // ---- helpers ----

    private String serviceToken(String clientId, String secret) throws Exception {
        String body = mockMvc.perform(post("/oauth2/token").header("Authorization", basic(clientId, secret))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=client_credentials"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(body, "$.access_token");
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes(StandardCharsets.UTF_8));
    }

    private UUID person(String name, RoleName role) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("dir-" + UUID.randomUUID() + "@example.com"), null);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of(name)), Instant.now());
            user.addRole(roles.findByName(role).orElseThrow());
            return users.saveAndFlush(user).getId();
        });
    }
}
