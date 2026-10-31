package com.swiftdrop.auth.token;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.api.DevTestTokenController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Lock 1: outside the dev profile the endpoint does not exist at all, even with the flag switched on. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest(properties = "swiftdrop.dev.test-tokens.enabled=true")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TestTokenEndpointAbsentIT {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApplicationContext context;

    @Test
    void controllerIsNotEvenCreated() {
        assertThat(context.getBeanNamesForType(DevTestTokenController.class)).isEmpty();
    }

    @Test
    void endpointAnswers404() throws Exception {
        mockMvc.perform(post("/api/v1/dev/test-tokens").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"ADMIN\"]}"))
                .andExpect(status().isNotFound());
    }
}
