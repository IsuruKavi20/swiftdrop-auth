package com.swiftdrop.auth.session;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.admin.RoleAdministration;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Refresh tokens end to end over HTTP: rotation, reuse detection, expiry, revocation, logout. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RefreshTokenIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final String AUTH = "/api/v1/auth";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private RoleRepository roles;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private RoleAdministration administration;

    @Test
    void loginReturnsARefreshTokenThatLastsOneDay() throws Exception {
        String email = verifiedUser(RoleName.CUSTOMER);

        mockMvc.perform(loginRequest(email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refresh_token").value(org.hamcrest.Matchers.matchesPattern("^[A-Za-z0-9_-]{43}$")))
                .andExpect(jsonPath("$.refresh_expires_in").value(86400));
    }

    @Test
    void refreshGivesNewTokensAndTheOldRefreshTokenStopsWorking() throws Exception {
        String first = login(verifiedUser(RoleName.CUSTOMER));

        String second = refreshOk(first);

        assertThat(second).isNotEqualTo(first);
        refresh(first).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));
    }

    @Test
    void reusingAnOldTokenKillsTheWholeSession() throws Exception {
        String stolen = login(verifiedUser(RoleName.CUSTOMER));
        String legit = refreshOk(stolen);

        refresh(stolen).andExpect(status().isUnauthorized());   // the copy comes back: theft detected

        refresh(legit).andExpect(status().isUnauthorized());    // so the newest token is dead too
        assertThat(reasonOf(legit)).isEqualTo("REUSE_DETECTED");
    }

    @Test
    void twoRefreshesAtTheSameMomentCannotBothSucceed() throws Exception {
        String token = login(verifiedUser(RoleName.CUSTOMER));
        CountDownLatch start = new CountDownLatch(1);
        List<Integer> statuses = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Future<?>> runs = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                runs.add(pool.submit(() -> {
                    start.await();
                    statuses.add(refresh(token).andReturn().getResponse().getStatus());
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

        assertThat(statuses).containsExactlyInAnyOrder(200, 401);
    }

    @Test
    void anIdleExpiredTokenIsRejected() throws Exception {
        String token = login(verifiedUser(RoleName.CUSTOMER));
        jdbc.update("UPDATE identity.refresh_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = ?",
                sha256(token));

        refresh(token).andExpect(status().isUnauthorized());
    }

    @Test
    void theSessionNeverOutlivesItsAbsoluteLimit() throws Exception {
        String token = login(verifiedUser(RoleName.CUSTOMER));
        jdbc.update("""
                UPDATE identity.refresh_tokens SET family_expires_at = now() + interval '1 hour',
                       expires_at = LEAST(expires_at, now() + interval '1 hour') WHERE token_hash = ?""", sha256(token));

        MvcResult result = refresh(token).andExpect(status().isOk()).andReturn();

        Integer remaining = JsonPath.read(result.getResponse().getContentAsString(), "$.refresh_expires_in");
        assertThat(remaining).isLessThanOrEqualTo(3600);
    }

    @Test
    void aDisabledAccountCannotRefreshAndItsSessionIsEnded() throws Exception {
        String email = verifiedUser(RoleName.CUSTOMER);
        String token = login(email);
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE email = ?", email);

        refresh(token).andExpect(status().isUnauthorized());

        assertThat(reasonOf(token)).isEqualTo("ACCOUNT_DISABLED");
    }

    @Test
    void aTemporarilyLockedAccountIsRefusedButItsSessionSurvives() throws Exception {
        String email = verifiedUser(RoleName.CUSTOMER);
        String token = login(email);
        jdbc.update("UPDATE identity.users SET locked_until = now() + interval '1 hour' WHERE email = ?", email);

        refresh(token).andExpect(status().isUnauthorized());
        assertThat(reasonOf(token)).isNull();   // a stranger's failed logins must not end the real session

        jdbc.update("UPDATE identity.users SET locked_until = NULL WHERE email = ?", email);
        refresh(token).andExpect(status().isOk());
    }

    @Test
    void theDatabaseRefusesASecondLiveTokenInOneSession() throws Exception {
        String token = login(verifiedUser(RoleName.CUSTOMER));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> jdbc.update("""
                        INSERT INTO identity.refresh_tokens (user_id, family_id, token_hash, created_at, expires_at,
                                                             family_expires_at)
                        SELECT user_id, family_id, repeat('a', 64), now(), expires_at, family_expires_at
                        FROM identity.refresh_tokens WHERE token_hash = ?""", sha256(token)))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void logoutAnswers204EvenForAnEmptyToken() throws Exception {
        mockMvc.perform(post(AUTH + "/logout").contentType(MediaType.APPLICATION_JSON).content("{\"refresh_token\":\"\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void aNewRoleAppearsInTheTokenAfterTheNextRefresh() throws Exception {
        String email = verifiedUser(RoleName.CUSTOMER);
        String token = login(email);
        administration.grant(UUID.randomUUID(), idOf(email), RoleName.COURIER);

        MvcResult result = refresh(token).andExpect(status().isOk()).andReturn();

        String access = JsonPath.read(result.getResponse().getContentAsString(), "$.access_token");
        assertThat(jwtDecoder.decode(access).getClaimAsStringList("roles")).containsExactly("COURIER", "CUSTOMER");
        assertThat(jwtDecoder.decode(access).getClaimAsStringList("entitlements")).contains("delivery:read-own");
    }

    @Test
    void removingARoleEndsAllSessionsOfThatUser() throws Exception {
        String email = verifiedUser(RoleName.CUSTOMER, RoleName.COURIER);
        String phone = login(email);
        String laptop = login(email);

        administration.revoke(UUID.randomUUID(), idOf(email), RoleName.COURIER);

        refresh(phone).andExpect(status().isUnauthorized());
        refresh(laptop).andExpect(status().isUnauthorized());
        assertThat(reasonOf(phone)).isEqualTo("ROLE_CHANGED");
    }

    @Test
    void logoutEndsTheSession() throws Exception {
        String token = login(verifiedUser(RoleName.CUSTOMER));

        mockMvc.perform(post(AUTH + "/logout").contentType(MediaType.APPLICATION_JSON).content(body(token)))
                .andExpect(status().isNoContent());

        refresh(token).andExpect(status().isUnauthorized());
        assertThat(reasonOf(token)).isEqualTo("LOGOUT");
    }

    @Test
    void logoutWithAnUnknownTokenLooksTheSame() throws Exception {
        mockMvc.perform(post(AUTH + "/logout").contentType(MediaType.APPLICATION_JSON).content(body("x".repeat(43))))
                .andExpect(status().isNoContent());
    }

    @Test
    void onlyTheHashIsStored() throws Exception {
        String token = login(verifiedUser(RoleName.CUSTOMER));

        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.refresh_tokens WHERE token_hash = ?",
                Integer.class, token)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.refresh_tokens WHERE token_hash = ?",
                Integer.class, sha256(token))).isOne();
    }

    @Test
    void aStaleBearerHeaderDoesNotBlockRefresh() throws Exception {
        String token = login(verifiedUser(RoleName.CUSTOMER));

        mockMvc.perform(post(AUTH + "/refresh").header("Authorization", "Bearer expired.or.garbage")
                        .contentType(MediaType.APPLICATION_JSON).content(body(token)))
                .andExpect(status().isOk());
    }

    // ---- helpers ----

    private org.springframework.test.web.servlet.RequestBuilder loginRequest(String email) {
        return post(AUTH + "/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}");
    }

    private String login(String email) throws Exception {
        MvcResult result = mockMvc.perform(loginRequest(email)).andExpect(status().isOk()).andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.refresh_token");
    }

    private org.springframework.test.web.servlet.ResultActions refresh(String token) throws Exception {
        return mockMvc.perform(post(AUTH + "/refresh").contentType(MediaType.APPLICATION_JSON).content(body(token)));
    }

    private String refreshOk(String token) throws Exception {
        MvcResult result = refresh(token).andExpect(status().isOk()).andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.refresh_token");
    }

    private static String body(String token) {
        return "{\"refresh_token\":\"" + token + "\"}";
    }

    private String verifiedUser(RoleName... roleNames) {
        String email = "session-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        String hash = encoder.encode(PASSWORD);
        transactions.executeWithoutResult(status -> {
            User user = new User(EmailAddress.of(email), hash);
            for (RoleName name : roleNames) {
                user.addRole(roles.findByName(name).orElseThrow());
            }
            user.markEmailVerified();
            users.saveAndFlush(user);
        });
        return email;
    }

    private UUID idOf(String email) {
        return users.findByEmail(email).orElseThrow().getId();
    }

    private String reasonOf(String token) {
        return jdbc.queryForObject("SELECT revoke_reason FROM identity.refresh_tokens WHERE token_hash = ?",
                String.class, sha256(token));
    }

    private static String sha256(String token) throws IllegalStateException {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
