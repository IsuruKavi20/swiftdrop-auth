package com.swiftdrop.auth.token.api;

import com.swiftdrop.auth.common.web.RequestIdFilter;
import com.swiftdrop.auth.common.web.RequestSizeLimitFilter;
import com.swiftdrop.auth.security.ProblemDetailsAccessDeniedHandler;
import com.swiftdrop.auth.security.ProblemDetailsAuthenticationEntryPoint;
import com.swiftdrop.auth.security.SecurityConfig;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.DevToolsSafetyCheck;
import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RolePermissions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The dev-only endpoint, with the dev profile and the flag switched on (as on a developer's laptop). */
@WebMvcTest(controllers = DevTestTokenController.class)
@Import({SecurityConfig.class, ProblemDetailsAuthenticationEntryPoint.class, ProblemDetailsAccessDeniedHandler.class,
        RequestIdFilter.class, RequestSizeLimitFilter.class})
@ActiveProfiles("dev")
@TestPropertySource(properties = "swiftdrop.dev.test-tokens.enabled=true")
class DevTestTokenControllerTest {

    private static final String TEST_TOKENS = "/api/v1/dev/test-tokens";
    private static final UUID COURIER_A = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private AccessTokenIssuer issuer;

    @MockitoBean
    private DevToolsSafetyCheck safetyCheck;

    @MockitoBean
    private RolePermissions rolePermissions;

    @Test
    void anyKnownRoleGetsATokenWithoutLogin() throws Exception {
        when(rolePermissions.permissionsOf(List.of(RoleName.COURIER)))
                .thenReturn(List.of("delivery:read-own", "delivery:update-status"));
        when(issuer.issueTestToken(eq(COURIER_A), eq(List.of("COURIER")),
                eq(List.of("delivery:read-own", "delivery:update-status"))))
                .thenReturn(new IssuedToken("test.jwt.value", Duration.ofMinutes(15)));

        request("{\"roles\":[\"COURIER\"],\"userId\":\"" + COURIER_A + "\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("test.jwt.value"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    void userIdIsOptional() throws Exception {
        when(issuer.issueTestToken(any(UUID.class), eq(List.of("ADMIN")), any()))
                .thenReturn(new IssuedToken("test.jwt.value", Duration.ofMinutes(15)));

        request("{\"roles\":[\"ADMIN\"]}").andExpect(status().isOk());
    }

    @Test
    void unknownRoleIsRejected() throws Exception {
        request("{\"roles\":[\"SUPERUSER\"]}")
                .andExpect(status().isBadRequest());
        verify(issuer, never()).issueTestToken(any(), any(), any());
    }

    @Test
    void atLeastOneRoleIsRequired() throws Exception {
        request("{\"roles\":[]}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    private ResultActions request(String json) throws Exception {
        return mockMvc.perform(post(TEST_TOKENS).contentType(MediaType.APPLICATION_JSON).content(json));
    }
}
