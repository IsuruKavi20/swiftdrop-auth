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
