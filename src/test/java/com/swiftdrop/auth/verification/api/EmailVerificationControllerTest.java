package com.swiftdrop.auth.verification.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.common.web.RequestIdFilter;
import com.swiftdrop.auth.common.web.ResponseTimeFloor;
import com.swiftdrop.auth.common.web.RequestSizeLimitFilter;
import com.swiftdrop.auth.security.ProblemDetailsAccessDeniedHandler;
import com.swiftdrop.auth.security.ProblemDetailsAuthenticationEntryPoint;
import com.swiftdrop.auth.security.SecurityConfig;
import com.swiftdrop.auth.verification.EmailVerificationService;
import com.swiftdrop.auth.verification.InvalidVerificationTokenException;
import com.swiftdrop.auth.verification.api.dto.ResendAcceptedResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = EmailVerificationController.class)
@Import({SecurityConfig.class, ProblemDetailsAuthenticationEntryPoint.class, ProblemDetailsAccessDeniedHandler.class,
        RequestIdFilter.class, RequestSizeLimitFilter.class, ResponseTimeFloor.class})
@TestPropertySource(properties = "swiftdrop.web.anti-enumeration-min-duration=0ms")
class EmailVerificationControllerTest {

    private static final String VERIFY = ApiPaths.AUTH + "/email-verification";
    private static final String RESEND = VERIFY + "/resend";
    private static final String TOKEN = "A".repeat(43);

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private EmailVerificationService service;

    @Test
    void validTokenGets204WithoutLoginAndNoReferrer() throws Exception {
        mockMvc.perform(post(VERIFY).contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + TOKEN + "\"}"))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Referrer-Policy", "no-referrer"));

        verify(service).verify(TOKEN);
    }

    @Test
    void badTokenGetsOneGenericAnswerAndIsNeverEchoed() throws Exception {
        doThrow(new InvalidVerificationTokenException()).when(service).verify(TOKEN);

        mockMvc.perform(post(VERIFY).contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + TOKEN + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_OR_EXPIRED_TOKEN"))
                .andExpect(content().string(not(containsString(TOKEN))));
    }

    @Test
    void verifyingByGetIsNotPossibleSoEmailScannersCannotBurnTokens() throws Exception {
        mockMvc.perform(get(VERIFY).param("token", TOKEN))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void resendAlwaysGets202WithTheSameMessage() throws Exception {
        mockMvc.perform(post(RESEND).contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"anyone@x.com\"}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value(ResendAcceptedResponse.ACCEPTED.message()));

        verify(service).requestResend("anyone@x.com");
    }
}
