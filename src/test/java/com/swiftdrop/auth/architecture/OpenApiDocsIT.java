package com.swiftdrop.auth.architecture;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class OpenApiDocsIT {

    @Nested
    @Import(TestcontainersConfiguration.class)
    @SpringBootTest(properties = {"springdoc.api-docs.enabled=true", "springdoc.swagger-ui.enabled=true"})
    @AutoConfigureMockMvc
    @ActiveProfiles("test")
    class WhenEnabledAsInDev {

        @Autowired
        private MockMvc mockMvc;

        @Test
        void documentsTheSignupContractWithoutLogin() throws Exception {
            mockMvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.info.title").value("SwiftDrop Identity & Auth Service"))
                    .andExpect(jsonPath("$.paths['/api/v1/auth/signup'].post.responses['202']").exists())
                    .andExpect(jsonPath("$.paths['/api/v1/auth/email-verification'].post").exists())
                    .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"));
        }

        /**
         * Production has no API map (/v3/api-docs is off), so the team gets the contract as a file instead:
         * regenerated on every build, it can never drift from the code. Import it into Swagger UI or Postman.
         */
        @Test
        void exportsTheContractForOtherTeams() throws Exception {
            String json = mockMvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            tools.jackson.databind.ObjectMapper mapper = new tools.jackson.databind.ObjectMapper();
            String pretty = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(mapper.readTree(json));

            java.nio.file.Path target = java.nio.file.Path.of("docs", "integration", "openapi.json");
            java.nio.file.Files.writeString(target, pretty + System.lineSeparator());

            org.assertj.core.api.Assertions.assertThat(pretty).contains("/api/v1/auth/login", "/oauth2/token");
            org.assertj.core.api.Assertions.assertThat(pretty).doesNotContain("/api/v1/dev/test-tokens");
        }

        @Test
        void requestDtoFieldsAreDocumentedButEntitiesAreNot() throws Exception {
            mockMvc.perform(get("/v3/api-docs"))
                    .andExpect(jsonPath("$.components.schemas.SignupRequest.properties.email").exists())
                    .andExpect(content().string(org.hamcrest.Matchers.not(containsString("passwordHash"))));
        }
    }

    @Nested
    @Import(TestcontainersConfiguration.class)
    @SpringBootTest
    @AutoConfigureMockMvc
    @ActiveProfiles("test")
    class WhenDisabledAsInProduction {

        @Autowired
        private MockMvc mockMvc;

        @Test
        void thereIsNoApiMap() throws Exception {
            mockMvc.perform(get("/v3/api-docs")).andExpect(status().isNotFound());
        }
    }
}
