package com.swiftdrop.auth.token;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Identity step 4a: OpenID Connect Discovery. Other services configure ONE value (the issuer) and find everything
 * else here; Spring's resource server does that with spring.security.oauth2.resourceserver.jwt.issuer-uri.
 */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OidcDiscoveryIT {

    private static final String DISCOVERY = "/.well-known/openid-configuration";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publishesTheIssuerAndWhereEverythingIsWithoutLogin() throws Exception {
        mockMvc.perform(get(DISCOVERY))
                .andExpect(status().isOk())
                // Spring and OIDC libraries refuse the document unless "issuer" equals the configured issuer exactly
                .andExpect(jsonPath("$.issuer").value("http://localhost"))
                .andExpect(jsonPath("$.jwks_uri").value("http://localhost/.well-known/jwks.json"))
                .andExpect(jsonPath("$.userinfo_endpoint").value("http://localhost/oauth2/userinfo"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost/oauth2/token"))
                .andExpect(header().string("Cache-Control", containsString("max-age")));
    }

    @Test
    void describesOnlyWhatWeReallySupport() throws Exception {
        mockMvc.perform(get(DISCOVERY))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported[0]").value("RS256"))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported", not(hasItem("none"))))
                .andExpect(jsonPath("$.subject_types_supported[0]").value("public"))
                .andExpect(jsonPath("$.scopes_supported", hasItem("openid")))
                .andExpect(jsonPath("$.claims_supported", hasItem("email_verified")))
                .andExpect(jsonPath("$.grant_types_supported[0]").value("client_credentials"))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported[0]").value("client_secret_basic"))
                // No browser redirect flow is offered (login is our own API): never advertise one
                .andExpect(jsonPath("$.authorization_endpoint").doesNotExist());
    }

    @Test
    void aStaleBearerHeaderDoesNotBreakDiscovery() throws Exception {
        mockMvc.perform(get(DISCOVERY).header("Authorization", "Bearer expired.or.garbage"))
                .andExpect(status().isOk());
    }
}
