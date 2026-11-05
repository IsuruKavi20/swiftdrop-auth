package com.swiftdrop.auth.google;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The browser side of Google login: the redirect to Google (PKCE, state, nonce), our success/failure redirects
 * to the frontend, and the one-time hand-off code exchange. Google itself is not called in tests.
 */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class GoogleLoginFlowIT {

    private static final String EXCHANGE = "/api/v1/auth/google/exchange";
    // RFC 7636 appendix B example pair: CHALLENGE = base64url(SHA-256(VERIFIER))
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private GoogleLoginSuccessHandler successHandler;

    @Autowired
    private GoogleLoginFailureHandler failureHandler;

    @Autowired
    private HandoffCodes handoffCodes;

    @Autowired
    private GoogleAccountLinker linker;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private org.springframework.session.SessionRepository<? extends org.springframework.session.Session> sessions;

    @Test
    void startingGoogleLoginRedirectsToGoogleWithPkceStateAndNonce() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/authorization/google").param("code_challenge", CHALLENGE))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith("https://accounts.google.com/");
        assertThat(location).contains("code_challenge=", "code_challenge_method=S256", "state=", "nonce=",
                "scope=openid%20email%20profile");
        assertThat(location).doesNotContain(CHALLENGE);   // OUR browser binding never goes to Google
        // The session lives in Redis (Spring Session): read it back the way any instance would
        String cookie = result.getResponse().getHeaders("Set-Cookie").stream()
                .filter(header -> header.startsWith("SWIFTDROP_LOGIN=")).findFirst().orElseThrow();
        String sessionId = new String(java.util.Base64.getDecoder().decode(
                cookie.substring("SWIFTDROP_LOGIN=".length(), cookie.indexOf(';'))), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(cookie).contains("HttpOnly", "SameSite=Lax").doesNotContain("Secure");   // Secure: prod only (https)
        assertThat((Object) sessions.findById(sessionId).getAttribute(GoogleLoginSuccessHandler.CHALLENGE_ATTRIBUTE))
                .isEqualTo(CHALLENGE);
    }

    @Test
    void successRedirectsToTheFrontendWithAOneTimeCodeInTheFragmentNeverTokens() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        successHandler.onAuthenticationSuccess(loginRequest(), response, googleLogin(uniqueSub(), true));

        URI redirect = URI.create(response.getRedirectedUrl());
        assertThat(redirect.getScheme() + "://" + redirect.getAuthority() + redirect.getPath())
                .isEqualTo("http://localhost:3000/auth/callback");
        assertThat(redirect.getQuery()).isNull();                     // nothing in ?query (logs, Referer)
        assertThat(redirect.getFragment()).matches("^code=[A-Za-z0-9_-]{43}$");
        assertThat(response.getRedirectedUrl()).doesNotContain("access_token", "eyJ");
    }

    @Test
    void theProfileInGooglesIdTokenIsSavedOnFirstLogin() throws Exception {
        String email = uniqueEmail();
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(60), Map.of(
                "iss", "https://accounts.google.com", "sub", uniqueSub(), "email", email, "email_verified", true,
                "name", "Isuru Kavinda", "given_name", "Isuru", "family_name", "Kavinda",
                "picture", "https://lh3.googleusercontent.com/a/photo", "locale", "si-LK"));
        DefaultOidcUser google = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")), idToken);

        successHandler.onAuthenticationSuccess(loginRequest(), new MockHttpServletResponse(),
                new OAuth2AuthenticationToken(google, google.getAuthorities(), "google"));

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT name, given_name, family_name, picture_url, locale FROM identity.users WHERE email = ?", email);
        assertThat(row).containsEntry("name", "Isuru Kavinda").containsEntry("given_name", "Isuru")
                .containsEntry("family_name", "Kavinda")
                .containsEntry("picture_url", "https://lh3.googleusercontent.com/a/photo")
                .containsEntry("locale", "si-LK");
    }

    @Test
    void aPhotoOnAnUntrustedHostIsDroppedButTheLoginWorks() throws Exception {
        String email = uniqueEmail();
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(60), Map.of(
                "iss", "https://accounts.google.com", "sub", uniqueSub(), "email", email, "email_verified", true,
                "name", "Isuru Kavinda", "picture", "https://tracker.example/pixel.png"));
        DefaultOidcUser google = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")), idToken);
        MockHttpServletResponse response = new MockHttpServletResponse();

        successHandler.onAuthenticationSuccess(loginRequest(), response,
                new OAuth2AuthenticationToken(google, google.getAuthorities(), "google"));

        assertThat(URI.create(response.getRedirectedUrl()).getFragment()).startsWith("code=");
        Map<String, Object> row = jdbc.queryForMap(
                "SELECT name, picture_url FROM identity.users WHERE email = ?", email);
        assertThat(row).containsEntry("name", "Isuru Kavinda");
        assertThat(row.get("picture_url")).isNull();
    }

    @Test
    void refusedGoogleAccountIsSentToTheFrontendWithAGenericError() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        successHandler.onAuthenticationSuccess(loginRequest(), response, googleLogin(uniqueSub(), false));

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:3000/auth/callback#error=login_failed");
    }

    @Test
    void aLoginStartedWithoutABrowserChallengeIsRefused() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        successHandler.onAuthenticationSuccess(new MockHttpServletRequest(), response, googleLogin(uniqueSub(), true));

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:3000/auth/callback#error=login_failed");
    }

    @Test
    void anInjectedCodeIsUselessWithoutTheVerifierOfTheBrowserThatStartedTheLogin() throws Exception {
        String attackersCode = codeForNewGoogleUser();

        exchange(attackersCode, "x".repeat(43)).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_LOGIN_CODE"));
        exchange(attackersCode).andExpect(status().isUnauthorized());   // and the code is burnt
    }

    @Test
    void twoRedeemsOfTheSameCodeAtTheSameMomentCannotBothSucceed() throws Exception {
        String code = codeForNewGoogleUser();
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.List<Integer> statuses = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.List<java.util.concurrent.Future<?>> runs = new java.util.ArrayList<>();
            for (int i = 0; i < 2; i++) {
                runs.add(pool.submit(() -> {
                    start.await();
                    statuses.add(exchange(code).andReturn().getResponse().getStatus());
                    return null;
                }));
            }
            start.countDown();
            for (java.util.concurrent.Future<?> run : runs) {
                run.get();
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(statuses).containsExactlyInAnyOrder(200, 401);
    }

    @Test
    void googleErrorsAndCancelGoToTheFrontendWithAGenericError() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        failureHandler.onAuthenticationFailure(new MockHttpServletRequest(), response,
                new BadCredentialsException("access_denied"));

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:3000/auth/callback#error=login_failed");
    }

    @Test
    void theHandoffCodeGivesOurNormalTokensExactlyOnce() throws Exception {
        String code = codeForNewGoogleUser();

        MvcResult result = exchange(code).andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.refresh_token").exists())
                .andReturn();
        assertThat((String) JsonPath.read(result.getResponse().getContentAsString(), "$.access_token")).startsWith("eyJ");

        exchange(code).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_LOGIN_CODE"));
    }

    @Test
    void anExpiredHandoffCodeIsRejected() throws Exception {
        String code = codeForNewGoogleUser();
        jdbc.update("""
                UPDATE identity.login_handoff_codes
                SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 second'
                WHERE code_hash = ?""", OpaqueTokens.hash(code));

        exchange(code).andExpect(status().isUnauthorized());
    }

    @Test
    void garbageCodesGetTheSameAnswer() throws Exception {
        exchange("x".repeat(43)).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_LOGIN_CODE"));
        exchange("not even close").andExpect(status().isUnauthorized());
    }

    @Test
    void aDisabledAccountCannotRedeemACodeIssuedBeforeIt() throws Exception {
        UUID userId = linker.link(GoogleIdentity.of(uniqueSub(), uniqueEmail(), true));
        String code = handoffCodes.issue(userId, CHALLENGE);
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE id = ?", userId);

        exchange(code).andExpect(status().isUnauthorized());
    }

    @Test
    void onlyTheHashOfTheCodeIsStored() throws Exception {
        String code = codeForNewGoogleUser();

        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.login_handoff_codes WHERE code_hash = ?",
                Integer.class, code)).isZero();
    }

    private org.springframework.test.web.servlet.ResultActions exchange(String code) throws Exception {
        return exchange(code, VERIFIER);
    }

    private org.springframework.test.web.servlet.ResultActions exchange(String code, String verifier) throws Exception {
        return mockMvc.perform(post(EXCHANGE).contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer stale.or.garbage")
                .content("{\"code\":\"" + code + "\",\"verifier\":\"" + verifier + "\"}"));
    }

    private String codeForNewGoogleUser() {
        return handoffCodes.issue(linker.link(GoogleIdentity.of(uniqueSub(), uniqueEmail(), true)), CHALLENGE);
    }

    private static MockHttpServletRequest loginRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(GoogleLoginSuccessHandler.CHALLENGE_ATTRIBUTE, CHALLENGE);
        return request;
    }

    private static OAuth2AuthenticationToken googleLogin(String sub, boolean emailVerified) {
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(60), Map.of(
                "iss", "https://accounts.google.com", "sub", sub, "email", uniqueEmail(),
                "email_verified", emailVerified));
        DefaultOidcUser user = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")), idToken);
        return new OAuth2AuthenticationToken(user, user.getAuthorities(), "google");
    }

    private static String uniqueEmail() {
        return "flow-" + UUID.randomUUID().toString().substring(0, 8) + "@gmail.com";
    }

    private static String uniqueSub() {
        return String.valueOf(Math.abs(UUID.randomUUID().getMostSignificantBits()));
    }
}
