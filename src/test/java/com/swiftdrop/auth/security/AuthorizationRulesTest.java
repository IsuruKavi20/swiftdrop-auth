package com.swiftdrop.auth.security;

import com.swiftdrop.auth.common.web.RequestIdFilter;
import com.swiftdrop.auth.common.web.RequestSizeLimitFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The authorization annotations, including the brief's required test:
 * "a courier cannot access another courier's deliveries". The deliveries controller below is TEST-ONLY
 * (real deliveries live in Module 3); it proves the ownership pattern teammates will use.
 */
@WebMvcTest(controllers = AuthorizationRulesTest.SampleDeliveriesController.class)
@Import({SecurityConfig.class, ProblemDetailsAuthenticationEntryPoint.class, ProblemDetailsAccessDeniedHandler.class,
        RequestIdFilter.class, RequestSizeLimitFilter.class, AuthorizationRulesTest.SampleDeliveriesController.class})
class AuthorizationRulesTest {

    private static final UUID COURIER_A = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID COURIER_B = UUID.fromString("22222222-2222-2222-2222-222222222222");

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    // ---- the brief's required test ----

    @Test
    void courierCannotSeeAnotherCouriersDeliveries() throws Exception {
        mockMvc.perform(get("/test/couriers/" + COURIER_B + "/deliveries")
                        .with(caller(COURIER_A, "ROLE_COURIER", "delivery:read-own")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void courierCanSeeTheirOwnDeliveries() throws Exception {
        mockMvc.perform(get("/test/couriers/" + COURIER_A + "/deliveries")
                        .with(caller(COURIER_A, "ROLE_COURIER", "delivery:read-own")))
                .andExpect(status().isOk());
    }

    @Test
    void dispatcherWithReadAllPermissionCanSeeAnyCouriersDeliveries() throws Exception {
        mockMvc.perform(get("/test/couriers/" + COURIER_B + "/deliveries")
                        .with(caller(UUID.randomUUID(), "ROLE_DISPATCHER", "delivery:read-all")))
                .andExpect(status().isOk());
    }

    // ---- role and permission annotations ----

    @Test
    void permissionAnnotationChecksTheExactPermission() throws Exception {
        mockMvc.perform(get("/test/parcels/assign").with(caller(UUID.randomUUID(), "ROLE_DISPATCHER", "parcel:assign")))
                .andExpect(status().isOk());
        mockMvc.perform(get("/test/parcels/assign").with(caller(UUID.randomUUID(), "ROLE_COURIER", "delivery:read-own")))
                .andExpect(status().isForbidden());
    }

    @Test
    void roleAnnotationChecksTheRole() throws Exception {
        mockMvc.perform(get("/test/admin-only").with(caller(UUID.randomUUID(), "ROLE_ADMIN")))
                .andExpect(status().isOk());
        mockMvc.perform(get("/test/admin-only").with(caller(UUID.randomUUID(), "ROLE_CUSTOMER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void anonymousCallerGets401NotData() throws Exception {
        mockMvc.perform(get("/test/couriers/" + COURIER_A + "/deliveries"))
                .andExpect(status().isUnauthorized());
    }

    private static RequestPostProcessor caller(UUID userId, String... authorities) {
        return jwt().jwt(token -> token.subject(userId.toString()))
                .authorities(Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toArray(GrantedAuthority[]::new));
    }

    @RestController
    static class SampleDeliveriesController {

        @GetMapping("/test/couriers/{courierId}/deliveries")
        @RequireOwnerOrPermission(owner = "#courierId", permission = "delivery:read-all")
        String deliveries(@PathVariable UUID courierId) {
            return "deliveries of " + courierId;
        }

        @GetMapping("/test/parcels/assign")
        @RequirePermission("parcel:assign")
        String assign() {
            return "assigned";
        }

        @GetMapping("/test/admin-only")
        @RequireRole("ADMIN")
        String adminOnly() {
            return "admin";
        }
    }
}
