package com.swiftdrop.auth.introspection;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.session.RevokeReason;
import com.swiftdrop.auth.session.SessionService;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Identity step 10: introspection (RFC 7662) answers "still OK right now?" with what can change within a token's
 * 15 minutes; revocation (RFC 7009) cancels a token. Only service clients with token:introspect may introspect.
 */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IntrospectionIT {

    private static final String BACKEND = "svc_swiftdrop-backend";
    private static final String BACKEND_SECRET = "events-poller-test-secret-0123456789abcdef";
    private static final String READER = "svc_swiftdrop-reader";
    private static final String READER_SECRET = "directory-reader-test-secret-0123456789abcdef";

    // Same receiver settings as EventPollIT and ErasureIT, so the test context is shared
    @DynamicPropertySource
    static void receiver(DynamicPropertyRegistry registry) {
        registry.add("swiftdrop.events.receivers[0].id", () -> "swiftdrop-backend");
        registry.add("swiftdrop.events.receivers[0].audience", () -> "swiftdrop-backend");
    }

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
    @Autowired
    private SessionService sessions;
    @Autowired
    private RevokedAccessTokens revoked;

    @Test
    void aFreshTokenIsActiveWithTheRolesAsTheyAreNow() throws Exception {
        UUID person = person();
        String token = tokenOf(person, List.of("CUSTOMER", "DISPATCHER"));   // the token claims more than is true

        introspect(token)
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.sub").value(person.toString()))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.roles", contains("CUSTOMER")))
                .andExpect(jsonPath("$.merchant_owner").doesNotExist())   // only merchant machine tokens have it
                .andExpect(jsonPath("$.exp").isNumber());
    }

    @Test
    void aBlockedPersonsTokenIsInactiveAtOnce() throws Exception {
        UUID person = person();
        String token = tokenOf(person, List.of("CUSTOMER"));
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE id = ?", person);

        introspect(token).andExpect(status().isOk()).andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.sub").doesNotExist());
    }

    @Test
    void tokensIssuedBeforeAllSessionsEndedAreInactive() throws Exception {
        UUID person = person();
        String old = tokenOf(person, List.of("CUSTOMER"));
        Thread.sleep(1100);   // tokens and the "valid after" time are whole seconds
        transactions.executeWithoutResult(status -> sessions.endAllSessions(person, RevokeReason.PASSWORD_CHANGED));

        introspect(old).andExpect(jsonPath("$.active").value(false));
        // a token handed out after that is fine
        introspect(tokenOf(person, List.of("CUSTOMER"))).andExpect(jsonPath("$.active").value(true));
    }

    @Test
    void garbageForeignAndExpiredTokensAreInactive() throws Exception {
        introspect("not-a-token").andExpect(jsonPath("$.active").value(false));
        introspect("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.").andExpect(jsonPath("$.active").value(false));
        // a merchant client that doesn't exist
        String machine = issuer.issueForClient("mc_doesnotexist", UUID.randomUUID(), List.of("MERCHANT"),
                List.of("merchant:api-access")).value();
        introspect(machine).andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void aServiceClientTokenIsActiveWhileTheClientIsConfigured() throws Exception {
        String service = issuer.issueForClient(READER, null, List.of("SERVICE"), List.of("directory:read")).value();
        introspect(service).andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.client_id").value(READER));
        String removed = issuer.issueForClient("svc_removed-client", null, List.of("SERVICE"), List.of()).value();
        introspect(removed).andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void onlyServiceClientsWithThePermissionMayIntrospect() throws Exception {
        String token = tokenOf(person(), List.of("CUSTOMER"));

        mockMvc.perform(post("/oauth2/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
        mockMvc.perform(post("/oauth2/introspect").header("Authorization", basic(BACKEND, "wrong-secret"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).param("token", token))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/oauth2/introspect").header("Authorization", basic(READER, READER_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).param("token", token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("unauthorized_client"));
        // a person's own token is no way in either
        mockMvc.perform(post("/oauth2/introspect").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).param("token", token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void aRevokedAccessTokenIsInactiveAndRevokeAlwaysSays200() throws Exception {
        String token = tokenOf(person(), List.of("CUSTOMER"));

        revoke(token).andExpect(status().isOk());
        revoke(token).andExpect(status().isOk());                 // again: fine
        revoke("nonsense-that-is-no-token").andExpect(status().isOk());

        introspect(token).andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void loggingOutEndsThatSessionsAccessTokensAtOnce() throws Exception {
        UUID person = person();
        com.swiftdrop.auth.session.SessionTokens login = transactions.execute(status ->
                sessions.start(users.findById(person).orElseThrow()));
        String access = login.accessToken().value();
        introspect(access).andExpect(jsonPath("$.active").value(true));

        revoke(login.refreshToken()).andExpect(status().isOk());   // same second: no gap thanks to the "sid" claim

        introspect(access).andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void cancelledTokensAreForgottenOnceTheyWouldHaveExpired() {
        jdbc.update("INSERT INTO identity.revoked_access_tokens (jti, expires_at) VALUES (?, ?)",
                "old-" + UUID.randomUUID(), Timestamp.from(Instant.now().minus(1, ChronoUnit.HOURS)));

        org.assertj.core.api.Assertions.assertThat(revoked.removeExpired()).isPositive();
    }

    @Test
    void discoveryNamesBothEndpoints() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(jsonPath("$.introspection_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/introspect")))
                .andExpect(jsonPath("$.revocation_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/revoke")))
                .andExpect(jsonPath("$.introspection_endpoint_auth_methods_supported", hasItem("client_secret_basic")));
    }

    private ResultActions introspect(String token) throws Exception {
        return mockMvc.perform(post("/oauth2/introspect").header("Authorization", basic(BACKEND, BACKEND_SECRET))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).param("token", token));
    }

    private ResultActions revoke(String token) throws Exception {
        return mockMvc.perform(post("/oauth2/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("token", token));
    }

    private String tokenOf(UUID person, List<String> roleNames) {
        return issuer.issue(person, TestPeople.SOMEONE, roleNames, List.of("parcel:create")).value();
    }

    private UUID person() {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("in-" + UUID.randomUUID().toString().substring(0, 8)
                    + "@example.com"), "{argon2}$argon2id$irrelevant");
            user.markEmailVerified();
            user.addRole(roles.findByName(RoleName.CUSTOMER).orElseThrow());
            return users.saveAndFlush(user).getId();
        });
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }
}
