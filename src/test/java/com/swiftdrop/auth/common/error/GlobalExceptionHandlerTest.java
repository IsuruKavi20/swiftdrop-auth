package com.swiftdrop.auth.common.error;

import com.swiftdrop.auth.security.ProblemDetailsAccessDeniedHandler;
import com.swiftdrop.auth.security.ProblemDetailsAuthenticationEntryPoint;
import com.swiftdrop.auth.security.SecurityConfig;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = {GlobalExceptionHandlerTest.ErrorScenariosController.class, ProblemErrorController.class})
@Import({SecurityConfig.class, ProblemDetailsAuthenticationEntryPoint.class,
        ProblemDetailsAccessDeniedHandler.class, GlobalExceptionHandlerTest.ErrorScenariosController.class})
class GlobalExceptionHandlerTest {

    private static final String PROBLEM_JSON = "application/problem+json";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void instanceIsARequestIdNotTheEchoedPath() throws Exception {
        mockMvc.perform(get("/test/<script>probe"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.instance").value(startsWith("urn:uuid:")))
                .andExpect(content().string(not(containsString("probe"))));
    }

    @Test
    @WithMockUser
    void mapKeysInFieldNamesAreNotEchoed() throws Exception {
        mockMvc.perform(post("/test/tags").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tags\":{\"evil-key-xyz\":\"\"}}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].field").value("tags[]"))
                .andExpect(content().string(not(containsString("evil-key-xyz"))));
    }

    @Test
    void containerErrorPageUsesProblemDetails() throws Exception {
        mockMvc.perform(get("/error").requestAttr("jakarta.servlet.error.status_code", 404))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
                .andExpect(jsonPath("$.code").value("NOT_FOUND"))
                .andExpect(content().string(not(containsString("path"))));
    }

    @Test
    void unauthenticatedRequestGets401ProblemDetails() throws Exception {
        mockMvc.perform(get("/test/ok"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"))
                .andExpect(jsonPath("$.type").value("https://swiftdrop.dev/problems/unauthenticated"));
    }

    @Test
    @WithMockUser
    void accessDeniedGets403ProblemDetails() throws Exception {
        mockMvc.perform(get("/test/forbidden"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    @WithMockUser
    void validationFailureListsFieldAndRuleButNeverTheValue() throws Exception {
        mockMvc.perform(post("/test/validated")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"\",\"secret\":\"tinysecret\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors[?(@.field == 'name')].rule").value("NotBlank"))
                .andExpect(jsonPath("$.errors[?(@.field == 'secret')].rule").value("Size"))
                .andExpect(content().string(not(containsString("tinysecret"))));
    }

    @Test
    @WithMockUser
    void malformedJsonGets400WithoutParserDetails() throws Exception {
        mockMvc.perform(post("/test/validated").contentType(MediaType.APPLICATION_JSON).content("{\"name\": "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"))
                .andExpect(content().string(not(containsString("Jackson"))))
                .andExpect(content().string(not(containsString("Unexpected end"))));
    }

    @Test
    @WithMockUser
    void domainExceptionUsesItsErrorCode() throws Exception {
        mockMvc.perform(get("/test/domain"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("EMAIL_ALREADY_USED"));
    }

    @Test
    @WithMockUser
    void optimisticLockConflictGets409() throws Exception {
        mockMvc.perform(get("/test/stale"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("CONFLICT"));
    }

    @Test
    @WithMockUser
    void unexpectedErrorGets500WithGenericMessageOnly() throws Exception {
        mockMvc.perform(get("/test/boom"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
                .andExpect(content().string(not(containsString("db-password-in-message"))))
                .andExpect(content().string(not(containsString("IllegalStateException"))));
    }

    @Test
    @WithMockUser
    void wrongMethodGets405() throws Exception {
        mockMvc.perform(post("/test/ok"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.code").value("METHOD_NOT_ALLOWED"));
    }

    @Test
    @WithMockUser
    void wrongContentTypeGets415() throws Exception {
        mockMvc.perform(post("/test/validated").contentType(MediaType.TEXT_PLAIN).content("hello"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"));
    }

    @Test
    @WithMockUser
    void unknownRouteGets404() throws Exception {
        mockMvc.perform(get("/test/does-not-exist"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));
    }

    record TaggedBody(Map<String, @NotBlank String> tags) {
    }

    record ValidatedBody(@NotBlank String name, @Size(min = 15) String secret) {
    }

    static class TestConflictException extends DomainException {
        TestConflictException() {
            super(ErrorCode.EMAIL_ALREADY_USED);
        }
    }

    @RestController
    static class ErrorScenariosController {

        @GetMapping("/test/ok")
        String ok() {
            return "ok";
        }

        @GetMapping("/test/forbidden")
        String forbidden() {
            throw new AccessDeniedException("internal reason");
        }

        @PostMapping(value = "/test/validated", consumes = MediaType.APPLICATION_JSON_VALUE)
        String validated(@Valid @RequestBody ValidatedBody body) {
            return "ok";
        }

        @PostMapping(value = "/test/tags", consumes = MediaType.APPLICATION_JSON_VALUE)
        String tags(@Valid @RequestBody TaggedBody body) {
            return "ok";
        }

        @GetMapping("/test/domain")
        String domain() {
            throw new TestConflictException();
        }

        @GetMapping("/test/stale")
        String stale() {
            throw new ObjectOptimisticLockingFailureException(Object.class, "id");
        }

        @GetMapping("/test/boom")
        String boom() {
            throw new IllegalStateException("db-password-in-message");
        }
    }
}
