package com.swiftdrop.auth.merchant;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.common.crypto.OpaqueTokens;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Merchant API credentials + the OAuth 2.0 client-credentials token endpoint (RFC 6749 4.4). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class MerchantClientCredentialsIT {

    private static final String CLIENTS = "/api/v1/merchants/me/clients";
    private static final String TOKEN = "/oauth2/token";
    private static final List<String> MERCHANT_PERMISSIONS =
            List.of("merchant:api-access", "merchant:api-booking", "parcel:create", "parcel:read-own");

    @Autowired
    com.swiftdrop.auth.user.RolePermissions rolePermissions;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private UserRepository users;

    @Autowired
    private RoleRepository roles;

    @Autowired
    private MerchantApplications applications;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Test
    void anApprovedMerchantCreatesCredentialsAndTheSecretIsShownOnceAndStoredHashed() throws Exception {
        UUID owner = approvedMerchant();

        MvcResult created = createClient(owner, "warehouse").andExpect(status().isCreated())
                .andExpect(jsonPath("$.clientId").value(org.hamcrest.Matchers.matchesPattern("^mc_[A-Za-z0-9_-]{22}$")))
                .andExpect(jsonPath("$.clientSecret").value(org.hamcrest.Matchers.matchesPattern("^[A-Za-z0-9_-]{43}$")))
                .andReturn();
        String secret = JsonPath.read(created.getResponse().getContentAsString(), "$.clientSecret");

        mockMvc.perform(get(CLIENTS).header("Authorization", merchantToken(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("warehouse"))
                .andExpect(jsonPath("$[0].clientSecret").doesNotExist());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.merchant_clients WHERE secret_hash = ?",
                Integer.class, OpaqueTokens.hash(secret))).isOne();
    }

    @Test
    void atMostTwoActiveClientsPerMerchant() throws Exception {
        UUID owner = approvedMerchant();
        createClient(owner, "one").andExpect(status().isCreated());
        createClient(owner, "two").andExpect(status().isCreated());

        createClient(owner, "three").andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MERCHANT_CLIENT_LIMIT"));
    }

    @Test
    void someoneWhoIsNotAMerchantCannotCreateCredentials() throws Exception {
        String customer = "Bearer " + issuer.issue(customer(), TestPeople.SOMEONE, List.of("CUSTOMER"),
                List.of("parcel:create", "parcel:read-own")).value();

        mockMvc.perform(post(CLIENTS).header("Authorization", customer).contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"x\"}")).andExpect(status().isForbidden());
    }

    @Test
    void theClientGetsAShortLivedMerchantTokenThatOurServicesAccept() throws Exception {
        UUID owner = approvedMerchant();
        String[] client = credentials(createClient(owner, "shop"));

        MvcResult result = token(client[0], client[1], "client_credentials").andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andReturn();

        Jwt jwt = jwtDecoder.decode(JsonPath.read(result.getResponse().getContentAsString(), "$.access_token"));
        assertThat(jwt.getSubject()).isEqualTo(client[0]);
        assertThat(jwt.getClaimAsString("client_id")).isEqualTo(client[0]);
        assertThat(jwt.getClaimAsString("merchant_id")).isNotBlank();
        assertThat(jwt.getClaimAsString("merchant_owner")).isEqualTo(owner.toString());   // services find the merchant by it
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("MERCHANT");
        assertThat(jwt.getClaimAsStringList("entitlements")).containsExactlyInAnyOrderElementsOf(MERCHANT_PERMISSIONS);
    }

    @Test
    void everyBadCredentialGetsTheSameInvalidClientAnswer() throws Exception {
        String[] client = credentials(createClient(approvedMerchant(), "shop"));

        String wrongSecret = body(token(client[0], "x".repeat(43), "client_credentials").andExpect(status().isUnauthorized()));
        String unknownId = body(token("mc_" + "A".repeat(22), client[1], "client_credentials").andExpect(status().isUnauthorized()));
        String noAuth = body(mockMvc.perform(post(TOKEN).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content("grant_type=client_credentials")).andExpect(status().isUnauthorized()));

        assertThat(wrongSecret).isEqualTo(unknownId).isEqualTo(noAuth).contains("\"error\":\"invalid_client\"");
    }

    @Test
    void onlyTheClientCredentialsGrantIsSupported() throws Exception {
        String[] client = credentials(createClient(approvedMerchant(), "shop"));

        token(client[0], client[1], "password").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    void aRevokedClientCanNoLongerGetTokens() throws Exception {
        UUID owner = approvedMerchant();
        String[] client = credentials(createClient(owner, "shop"));

        mockMvc.perform(delete(CLIENTS + "/" + client[0]).header("Authorization", merchantToken(owner)))
                .andExpect(status().isNoContent());

        token(client[0], client[1], "client_credentials").andExpect(status().isUnauthorized());
    }

    @Test
    void aSuspendedMerchantsClientsStopWorking() throws Exception {
        UUID owner = approvedMerchant();
        String[] client = credentials(createClient(owner, "shop"));
        jdbc.update("UPDATE identity.merchants SET status = 'SUSPENDED' WHERE user_id = ?", owner);

        token(client[0], client[1], "client_credentials").andExpect(status().isUnauthorized());
    }

    @Test
    void anotherMerchantCannotRevokeMyClient() throws Exception {
        String[] mine = credentials(createClient(approvedMerchant(), "shop"));
        UUID other = approvedMerchant();

        mockMvc.perform(delete(CLIENTS + "/" + mine[0]).header("Authorization", merchantToken(other)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("MERCHANT_CLIENT_NOT_FOUND"));
        token(mine[0], mine[1], "client_credentials").andExpect(status().isOk());
    }

    @Test
    void aStrangersPasswordGuessesDoNotBreakTheMerchantsIntegration() throws Exception {
        UUID owner = approvedMerchant();
        String[] client = credentials(createClient(owner, "shop"));
        jdbc.update("UPDATE identity.users SET locked_until = now() + interval '15 minutes' WHERE id = ?", owner);

        token(client[0], client[1], "client_credentials").andExpect(status().isOk());
    }

    @Test
    void noPersonsRoleEverGivesTheApiBookingPermission() {
        // Only merchant machine tokens carry it (MerchantClients adds it); a person's login token never can
        assertThat(rolePermissions.permissionsOf(java.util.EnumSet.allOf(com.swiftdrop.auth.user.RoleName.class)))
                .doesNotContain("merchant:api-booking");
    }

    @Test
    void aMachineTokenIsNotAPerson() throws Exception {
        String[] client = credentials(createClient(approvedMerchant(), "shop"));
        String machine = "Bearer " + JsonPath.read(body(token(client[0], client[1], "client_credentials")), "$.access_token");

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", machine)).andExpect(status().isUnauthorized());
        mockMvc.perform(post(CLIENTS).header("Authorization", machine).contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"more\"}")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/admin/users").param("email", "a@b.com").header("Authorization", machine))
                .andExpect(status().isForbidden());   // lacks user:read; never a 500
    }

    @Test
    void basicHeaderVariantsAreHandledSafely() throws Exception {
        String[] client = credentials(createClient(approvedMerchant(), "shop"));
        String encoded = Base64.getEncoder().encodeToString((client[0] + ":" + client[1]).getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(post(TOKEN).header("Authorization", "basic " + encoded)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=client_credentials"))
                .andExpect(status().isOk());   // the scheme name is case-insensitive (RFC 9110)
        for (String bad : new String[] {"Basic !!!not-base64", "Basic " + Base64.getEncoder().encodeToString(
                "no-colon".getBytes(StandardCharsets.UTF_8)), "Bearer x"}) {
            mockMvc.perform(post(TOKEN).header("Authorization", bad)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=client_credentials"))
                    .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
        }
    }

    // ---- helpers ----

    private ResultActions createClient(UUID owner, String name) throws Exception {
        return mockMvc.perform(post(CLIENTS).header("Authorization", merchantToken(owner))
                .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"" + name + "\"}"));
    }

    private static String[] credentials(ResultActions created) throws Exception {
        String json = created.andReturn().getResponse().getContentAsString();
        return new String[] {JsonPath.read(json, "$.clientId"), JsonPath.read(json, "$.clientSecret")};
    }

    private ResultActions token(String clientId, String secret, String grantType) throws Exception {
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        return mockMvc.perform(post(TOKEN).header("Authorization", "Basic " + basic)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("grant_type=" + grantType));
    }

    private static String body(ResultActions result) throws Exception {
        return result.andReturn().getResponse().getContentAsString();
    }

    private String merchantToken(UUID owner) {
        return "Bearer " + issuer.issue(owner, TestPeople.SOMEONE, List.of("CUSTOMER", "MERCHANT"), MERCHANT_PERMISSIONS).value();
    }

    private UUID approvedMerchant() {
        UUID owner = customer();
        UUID merchantId = applications.apply(owner,
                new MerchantApplications.Application("Shop " + owner.toString().substring(0, 6),
                "PV-" + owner.toString().substring(0, 8), null)).id();
        applications.decide(customer(), merchantId, MerchantApplications.Decision.APPROVE, null);
        return owner;
    }

    private UUID customer() {
        String email = "mc-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), "{argon2}$argon2id$irrelevant");
            user.addRole(roles.findByName(RoleName.CUSTOMER).orElseThrow());
            user.markEmailVerified();
            return users.saveAndFlush(user).getId();
        });
    }
}
