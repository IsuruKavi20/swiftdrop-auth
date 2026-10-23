package com.swiftdrop.auth.common.web;

import com.swiftdrop.auth.security.ProblemDetailsAccessDeniedHandler;
import com.swiftdrop.auth.security.ProblemDetailsAuthenticationEntryPoint;
import com.swiftdrop.auth.security.SecurityConfig;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = RequestHandlingTest.EchoController.class)
@Import({SecurityConfig.class, ProblemDetailsAuthenticationEntryPoint.class, ProblemDetailsAccessDeniedHandler.class,
        RequestIdFilter.class, RequestSizeLimitFilter.class, RequestHandlingTest.EchoController.class})
class RequestHandlingTest {

    private static final String ECHO = ApiPaths.V1 + "/test/echo";
    private static final String UUID_PATTERN = "^[0-9a-f-]{36}$";

    @Autowired
    private MockMvc mockMvc;

    // ---- D1: request IDs ----

    @Test
    @WithMockUser
    void everyResponseGetsAGeneratedRequestId() throws Exception {
        mockMvc.perform(post(ECHO).contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"isuru\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string(RequestIdFilter.HEADER, matchesPattern(UUID_PATTERN)));
    }

    @Test
    void wellFormedClientRequestIdIsKeptAndAppearsInErrorBody() throws Exception {
        mockMvc.perform(get("/nowhere").header(RequestIdFilter.HEADER, "client-trace-12345"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(RequestIdFilter.HEADER, "client-trace-12345"))
                .andExpect(jsonPath("$.requestId").value("client-trace-12345"));
    }

    @Test
    void unsafeClientRequestIdIsReplaced() throws Exception {
        mockMvc.perform(get("/nowhere").header(RequestIdFilter.HEADER, "abc\r\nFAKE LOG LINE"))
                .andExpect(header().string(RequestIdFilter.HEADER, matchesPattern(UUID_PATTERN)))
                .andExpect(content().string(not(containsString("FAKE"))));
    }

    // ---- D3: strict JSON ----

    @Test
    @WithMockUser
    void unknownFieldIsRejected() throws Exception {
        mockMvc.perform(post(ECHO).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"isuru\",\"role\":\"ADMIN\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"))
                .andExpect(content().string(not(containsString("role"))));
    }

    @Test
    @WithMockUser
    void duplicateKeyIsRejected() throws Exception {
        mockMvc.perform(post(ECHO).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"isuru\",\"name\":\"admin\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));
    }

    @Test
    @WithMockUser
    void trailingContentAfterJsonIsRejected() throws Exception {
        mockMvc.perform(post(ECHO).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"isuru\"} {\"name\":\"other\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));
    }

    // ---- D4 / D5: size and content type ----

    @Test
    void bodyLargerThanLimitGets413() throws Exception {
        String huge = "{\"name\":\"" + "a".repeat(RequestSizeLimitFilter.MAX_BODY_BYTES) + "\"}";

        mockMvc.perform(post(ECHO).contentType(MediaType.APPLICATION_JSON).content(huge))
                .andExpect(status().isContentTooLarge())
                .andExpect(jsonPath("$.code").value("PAYLOAD_TOO_LARGE"));
    }

    @Test
    @WithMockUser
    void nonJsonBodyGets415() throws Exception {
        mockMvc.perform(post(ECHO).contentType(MediaType.TEXT_PLAIN).content("name=isuru"))
                .andExpect(status().isUnsupportedMediaType());
    }

    // ---- D6: caching ----

    @Test
    @WithMockUser
    void responsesAreNeverCached() throws Exception {
        mockMvc.perform(post(ECHO).contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"isuru\"}"))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    record EchoRequest(@NotBlank String name) {
    }

    record EchoResponse(String name) {
    }

    @RestController
    static class EchoController {

        @PostMapping(value = ECHO, consumes = MediaType.APPLICATION_JSON_VALUE)
        EchoResponse echo(@Valid @RequestBody EchoRequest request) {
            return new EchoResponse(request.name());
        }
    }
}
