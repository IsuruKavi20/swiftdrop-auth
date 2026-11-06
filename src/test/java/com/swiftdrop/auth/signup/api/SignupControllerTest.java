package com.swiftdrop.auth.signup.api;

import com.swiftdrop.auth.common.concurrency.ServiceBusyException;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.common.web.RequestIdFilter;
import com.swiftdrop.auth.common.web.ResponseTimeFloor;
import com.swiftdrop.auth.common.web.RequestSizeLimitFilter;
import com.swiftdrop.auth.security.ProblemDetailsAccessDeniedHandler;
import com.swiftdrop.auth.security.ProblemDetailsAuthenticationEntryPoint;
import com.swiftdrop.auth.security.SecurityConfig;
import com.swiftdrop.auth.signup.SignupOutcome;
import com.swiftdrop.auth.signup.SignupService;
import com.swiftdrop.auth.signup.WeakPasswordException;
import com.swiftdrop.auth.signup.api.dto.SignupAcceptedResponse;
import com.swiftdrop.auth.signup.api.dto.SignupRequest;
import com.swiftdrop.auth.user.InvalidEmailException;
import com.swiftdrop.auth.user.InvalidPersonNameException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = SignupController.class)
@Import({SecurityConfig.class, ProblemDetailsAuthenticationEntryPoint.class, ProblemDetailsAccessDeniedHandler.class,
        RequestIdFilter.class, RequestSizeLimitFilter.class, ResponseTimeFloor.class})
// Rate limits have their own tests (RateLimitFilterTest, RateLimitIT); here they would only get in the way
@TestPropertySource(properties = {"swiftdrop.web.anti-enumeration-min-duration=0ms", "swiftdrop.rate-limit.enabled=false"})
class SignupControllerTest {

    private static final String SIGNUP = ApiPaths.AUTH + "/signup";
    private static final String NAME = "Isuru Kavinda";
    private static final String PASSWORD = "a long secret passphrase";

    @Autowired
    private MockMvc mockMvc;

    // The filter chain is a resource server and needs a decoder; these tests don't use tokens
    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private SignupService signupService;

    @Test
    void newAccountGets202WithoutLogin() throws Exception {
        when(signupService.signUp(NAME, "isuru@x.com", PASSWORD)).thenReturn(SignupOutcome.ACCOUNT_CREATED);

        signUp("{\"name\":\"" + NAME + "\",\"email\":\"isuru@x.com\",\"password\":\"" + PASSWORD + "\"}")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value(SignupAcceptedResponse.ACCEPTED.message()))
                .andExpect(header().exists(RequestIdFilter.HEADER))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    void existingAccountGetsExactlyTheSameResponse() throws Exception {
        when(signupService.signUp(NAME, "taken@x.com", PASSWORD)).thenReturn(SignupOutcome.EMAIL_ALREADY_REGISTERED);

        signUp("{\"name\":\"" + NAME + "\",\"email\":\"taken@x.com\",\"password\":\"" + PASSWORD + "\"}")
                .andExpect(status().isAccepted())
                .andExpect(content().json("{\"message\":\"" + SignupAcceptedResponse.ACCEPTED.message() + "\"}", true));
    }

    @Test
    void weakPasswordGets400WithTheReasonButNotThePassword() throws Exception {
        when(signupService.signUp(NAME, "isuru@x.com", "tinypass")).thenThrow(new WeakPasswordException("TooShort"));

        signUp("{\"name\":\"" + NAME + "\",\"email\":\"isuru@x.com\",\"password\":\"tinypass\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("WEAK_PASSWORD"))
                .andExpect(jsonPath("$.errors[0].field").value("password"))
                .andExpect(jsonPath("$.errors[0].rule").value("TooShort"))
                .andExpect(content().string(not(containsString("tinypass"))));
    }

    @Test
    void busyServerGets503WithRetryAfter() throws Exception {
        when(signupService.signUp(NAME, "isuru@x.com", PASSWORD)).thenThrow(new ServiceBusyException());

        signUp("{\"name\":\"" + NAME + "\",\"email\":\"isuru@x.com\",\"password\":\"" + PASSWORD + "\"}")
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Retry-After", "1"))
                .andExpect(jsonPath("$.code").value("SERVICE_BUSY"));
    }

    @Test
    void invalidEmailGets400() throws Exception {
        when(signupService.signUp(NAME, "nope", PASSWORD)).thenThrow(new InvalidEmailException());

        signUp("{\"name\":\"" + NAME + "\",\"email\":\"nope\",\"password\":\"" + PASSWORD + "\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EMAIL"));
    }

    @Test
    void missingNameGets400BeforeTheServiceIsCalled() throws Exception {
        signUp("{\"email\":\"isuru@x.com\",\"password\":\"" + PASSWORD + "\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));

        verify(signupService, never()).signUp(anyString(), anyString(), anyString());
    }

    @Test
    void invalidNameGets400WithoutEchoingIt() throws Exception {
        when(signupService.signUp("Bad\u202Ename", "isuru@x.com", PASSWORD)).thenThrow(new InvalidPersonNameException());

        signUp("{\"name\":\"Bad\u202Ename\",\"email\":\"isuru@x.com\",\"password\":\"" + PASSWORD + "\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_NAME"))
                .andExpect(content().string(not(containsString("Bad"))));
    }

    @Test
    void missingFieldsGet400BeforeTheServiceIsCalled() throws Exception {
        signUp("{\"name\":\"" + NAME + "\",\"email\":\"\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));

        verify(signupService, never()).signUp(anyString(), anyString(), anyString());
    }

    @Test
    void extraFieldsLikeRoleAreRejected() throws Exception {
        signUp("{\"name\":\"" + NAME + "\",\"email\":\"isuru@x.com\",\"password\":\"" + PASSWORD + "\",\"role\":\"ADMIN\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));

        verify(signupService, never()).signUp(anyString(), anyString(), anyString());
    }

    @Test
    void requestDtoNeverPrintsThePassword() {
        assertThatToString(new SignupRequest(NAME, "isuru@x.com", PASSWORD).toString());
    }

    private static void assertThatToString(String text) {
        org.assertj.core.api.Assertions.assertThat(text).doesNotContain(PASSWORD).doesNotContain("isuru@x.com").doesNotContain(NAME);
    }

    private ResultActions signUp(String json) throws Exception {
        return mockMvc.perform(post(SIGNUP).contentType(MediaType.APPLICATION_JSON).content(json));
    }
}
