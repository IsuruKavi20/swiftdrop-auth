package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.MailpitClient;
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

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Email links lead back to the app the person signed up on, found ONLY by an exact Origin match. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EmailLinkFrontendIT {

    private static final String PASSWORD = "correct horse battery staple 42";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MailpitClient mailpit;

    @Test
    void emailLinkGoesToTheAppTheSignupCameFrom() throws Exception {
        String email = uniqueEmail();

        mockMvc.perform(signup(email).header("Origin", "https://app.getswiftdrop.me")).andExpect(status().isAccepted());

        assertThat(mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT).text())
                .contains("https://app.getswiftdrop.me/verify-email#token=");
    }

    @Test
    void noUrlFromTheRequestIsEverUsed() throws Exception {
        // No Origin (e.g. curl) and a misleading Host/Referer: the link goes to the primary app
        String email = uniqueEmail();

        mockMvc.perform(signup(email).header("Host", "evil.example").header("Referer", "https://evil.example/"))
                .andExpect(status().isAccepted());

        String text = mailpit.awaitMessageTo(email, SmtpAccountEmailSender.VERIFY_SUBJECT).text();
        assertThat(text).contains("http://localhost:3000/verify-email#token=").doesNotContain("evil.example");
    }

    private static MockHttpServletRequestBuilder signup(String email) {
        return post("/api/v1/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Link Test\",\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}");
    }

    private static String uniqueEmail() {
        return "link-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
