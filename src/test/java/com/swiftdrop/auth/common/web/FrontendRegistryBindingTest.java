package com.swiftdrop.auth.common.web;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The list binds from the environment variables Helm sets, and a bad list stops the start. */
class FrontendRegistryBindingTest {

    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withUserConfiguration(Config.class);

    @Test
    void bindsFromHelmStyleEnvironmentVariables() {
        context.withInitializer(app -> app.getEnvironment().getPropertySources().addFirst(
                        new SystemEnvironmentPropertySource("test-systemEnvironment", Map.of(
                                "SWIFTDROP_FRONTENDS_0_ID", "local",
                                "SWIFTDROP_FRONTENDS_0_BASEURL", "http://localhost:5173",
                                "SWIFTDROP_FRONTENDS_0_PRIMARY", "true",
                                "SWIFTDROP_FRONTENDS_1_ID", "web",
                                "SWIFTDROP_FRONTENDS_1_BASEURL", "https://app.getswiftdrop.me",
                                "SWIFTDROP_FRONTENDS_1_PRIMARY", "false"))))
                .run(app -> {
                    FrontendRegistry registry = app.getBean(FrontendRegistry.class);
                    assertThat(registry.origins()).containsExactly("http://localhost:5173", "https://app.getswiftdrop.me");
                    assertThat(registry.link(null, "/x")).isEqualTo(URI.create("http://localhost:5173/x"));
                });
    }

    @Test
    void noFrontendsMeansNoStart() {
        context.run(app -> assertThat(app).hasFailed());
    }

    @Test
    void anUnsafeEntryMeansNoStart() {
        context.withPropertyValues("swiftdrop.frontends[0].id=web",
                        "swiftdrop.frontends[0].base-url=http://app.getswiftdrop.me",
                        "swiftdrop.frontends[0].primary=true")
                .run(app -> assertThat(app).hasFailed());
    }

    @Configuration
    @EnableConfigurationProperties(FrontendRegistry.class)
    static class Config {
    }
}
