package com.swiftdrop.auth.common.web;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The whole app with a tiny login limit: the third attempt from one IP gets our standard 429. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest(properties = {
        "swiftdrop.rate-limit.enabled=true",
        "swiftdrop.rate-limit.rules[0].name=login",
        "swiftdrop.rate-limit.rules[0].method=POST",
        "swiftdrop.rate-limit.rules[0].path=/api/v1/auth/login",
        "swiftdrop.rate-limit.rules[0].per-minute=2"})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RateLimitIT {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void theThirdLoginInAMinuteFromOneIpIsRateLimited() throws Exception {
        mockMvc.perform(login("192.0.2.10")).andExpect(status().isUnauthorized());
        mockMvc.perform(login("192.0.2.10")).andExpect(status().isUnauthorized());

        mockMvc.perform(login("192.0.2.10"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", matchesPattern("^[1-9][0-9]?$")))
                .andExpect(header().exists("X-Request-Id"))
                .andExpect(jsonPath("$.code").value("RATE_LIMITED"));

        mockMvc.perform(login("192.0.2.99")).andExpect(status().isUnauthorized());   // another IP is fine
    }

    private static MockHttpServletRequestBuilder login(String ip) {
        return post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"nobody@example.com\",\"password\":\"whatever whatever\"}")
                .with(request -> {
                    request.setRemoteAddr(ip);
                    return request;
                });
    }
}
