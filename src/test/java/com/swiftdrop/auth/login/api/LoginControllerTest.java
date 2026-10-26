package com.swiftdrop.auth.login.api;

import com.swiftdrop.auth.common.concurrency.ServiceBusyException;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.common.web.RequestIdFilter;
import com.swiftdrop.auth.common.web.RequestSizeLimitFilter;
import com.swiftdrop.auth.login.EmailNotVerifiedException;
import com.swiftdrop.auth.login.InvalidCredentialsException;
import com.swiftdrop.auth.login.LoginService;
import com.swiftdrop.auth.login.api.dto.LoginRequest;
import com.swiftdrop.auth.security.ProblemDetailsAccessDeniedHandler;
import com.swiftdrop.auth.security.ProblemDetailsAuthenticationEntryPoint;
import com.swiftdrop.auth.security.SecurityConfig;
import com.swiftdrop.auth.token.IssuedToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = LoginController.class)
@Import({SecurityConfig.class, ProblemDetailsAuthenticationEntryPoint.class, ProblemDetailsAccessDeniedHandler.class,
        RequestIdFilter.class, RequestSizeLimitFilter.class})
class LoginControllerTest {

    private static final String LOGIN = ApiPaths.AUTH + "/login";
    private static final String PASSWORD = "my parcel arrives on tuesday";

    @Autowired
    private MockMvc mockMvc;

    // The filter chain is a resource server and needs a decoder; these tests don't use tokens
    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private LoginService loginService;

    @Test
    void successReturnsAStandardBearerTokenResponseThatIsNeverCached() throws Exception {
        when(loginService.login("isuru@x.com", PASSWORD))
                .thenReturn(new IssuedToken("signed.jwt.value", Duration.ofMinutes(15)));

        login("isuru@x.com", PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("signed.jwt.value"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(header().string("Pragma", "no-cache"));
    }

    @Test
    void everyCredentialFailureLooksIdentical() throws Exception {
        when(loginService.login("a@x.com", PASSWORD)).thenThrow(new InvalidCredentialsException());
        when(loginService.login("b@x.com", PASSWORD)).thenThrow(new InvalidCredentialsException());

        String first = bodyWithoutRequestIds(login("a@x.com", PASSWORD).andExpect(status().isUnauthorized()));
        String second = bodyWithoutRequestIds(login("b@x.com", PASSWORD).andExpect(status().isUnauthorized()));

        assertThat(first).isEqualTo(second).contains("INVALID_CREDENTIALS");
    }

    @Test
    void unverifiedEmailAfterCorrectPasswordGets403() throws Exception {
        when(loginService.login("isuru@x.com", PASSWORD)).thenThrow(new EmailNotVerifiedException());

        login("isuru@x.com", PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));
    }

    @Test
    void busyServerGets503() throws Exception {
        when(loginService.login("isuru@x.com", PASSWORD)).thenThrow(new ServiceBusyException());

        login("isuru@x.com", PASSWORD)
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Retry-After", "1"));
    }

    @Test
    void passwordIsNeverEchoedAndExtraFieldsAreRejected() throws Exception {
        mockMvc.perform(post(LOGIN).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"isuru@x.com\",\"password\":\"" + PASSWORD + "\",\"role\":\"ADMIN\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString(PASSWORD))));
    }

    @Test
    void requestDtoNeverPrintsCredentials() {
        assertThat(new LoginRequest("isuru@x.com", PASSWORD).toString())
                .doesNotContain(PASSWORD).doesNotContain("isuru@x.com");
    }

    private ResultActions login(String email, String password) throws Exception {
        return mockMvc.perform(post(LOGIN).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"));
    }

    private static String bodyWithoutRequestIds(ResultActions result) throws Exception {
        return result.andReturn().getResponse().getContentAsString()
                .replaceAll("\"requestId\":\"[^\"]+\"", "").replaceAll("\"instance\":\"[^\"]+\"", "");
    }
}
