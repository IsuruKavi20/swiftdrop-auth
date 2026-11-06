package com.swiftdrop.auth.token;

import com.jayway.jsonpath.JsonPath;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PersonName;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 4b, end to end: login and refresh hand out an ID token; the API refuses it as a bearer token. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdTokenIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private TransactionTemplate transactions;

    @Test
    void loginAndRefreshReturnAnIdTokenWithTheProfile() throws Exception {
        String email = uniqueEmail();
        namedUser(email);

        String login = mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String idToken = JsonPath.read(login, "$.id_token");
        assertThat(claim(idToken, "name")).isEqualTo("Nimal Perera");

        String refreshed = mockMvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refresh_token\":\"" + JsonPath.read(login, "$.refresh_token") + "\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat((String) JsonPath.read(refreshed, "$.id_token")).isNotBlank();
    }

    @Test
    void theApiRefusesAnIdTokenUsedAsABearerToken() throws Exception {
        String email = uniqueEmail();
        namedUser(email);
        String login = mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String idToken = JsonPath.read(login, "$.id_token");

        mockMvc.perform(get("/api/v1/me/profile").header("Authorization", "Bearer " + idToken))
                .andExpect(status().isUnauthorized());
    }

    // Reads a claim without verifying (the unit test verifies signatures; here we only look at the content)
    private static Object claim(String jwt, String name) throws Exception {
        return com.nimbusds.jwt.SignedJWT.parse(jwt).getJWTClaimsSet().getClaim(name);
    }

    private void namedUser(String email) {
        String hash = encoder.encode(PASSWORD);
        transactions.executeWithoutResult(status -> {
            User user = new User(EmailAddress.of(email), hash);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), Instant.now());
            users.saveAndFlush(user);
        });
    }

    private static String uniqueEmail() {
        return "idtoken-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
