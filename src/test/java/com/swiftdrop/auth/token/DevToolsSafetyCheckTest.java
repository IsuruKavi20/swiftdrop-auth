package com.swiftdrop.auth.token;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Lock 3: production refuses to start if the test-token endpoint is switched on. */
class DevToolsSafetyCheckTest {

    @Test
    void productionWithTestTokensEnabledRefusesToStart() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("swiftdrop.dev.test-tokens.enabled", "true");
        environment.setActiveProfiles("prod");

        assertThatThrownBy(() -> new DevToolsSafetyCheck(environment).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("test-tokens");
    }

    @Test
    void productionWithoutTestTokensStartsNormally() {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles("prod");

        assertThatCode(() -> new DevToolsSafetyCheck(environment).afterPropertiesSet()).doesNotThrowAnyException();
    }

    @Test
    void developmentOnLocalhostMayEnableThem() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("swiftdrop.dev.test-tokens.enabled", "true")
                .withProperty("swiftdrop.jwt.issuer", "http://localhost:8080");
        environment.setActiveProfiles("dev");

        assertThatCode(() -> new DevToolsSafetyCheck(environment).afterPropertiesSet()).doesNotThrowAnyException();
    }

    @Test
    void devProfileDeployedOnARealServerRefusesToStart() {
        // e.g. a staging host started with SPRING_PROFILES_ACTIVE=dev and a real issuer URL
        MockEnvironment environment = new MockEnvironment()
                .withProperty("swiftdrop.dev.test-tokens.enabled", "true")
                .withProperty("swiftdrop.jwt.issuer", "https://auth-staging.swiftdrop.dev");
        environment.setActiveProfiles("dev");

        assertThatThrownBy(() -> new DevToolsSafetyCheck(environment).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("developer's machine");
    }

    @Test
    void aProfileNamedDifferentlyThanProdIsStillCaughtByTheIssuerCheck() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("swiftdrop.dev.test-tokens.enabled", "true")
                .withProperty("swiftdrop.jwt.issuer", "https://auth.swiftdrop.dev");
        environment.setActiveProfiles("dev", "production");

        assertThatThrownBy(() -> new DevToolsSafetyCheck(environment).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void environmentVariableSpellingOfTheFlagIsRecognised() {
        // Spring Boot relaxed binding maps SWIFTDROP_DEV_TESTTOKENS_ENABLED to swiftdrop.dev.test-tokens.enabled
        org.springframework.core.env.StandardEnvironment environment = new org.springframework.core.env.StandardEnvironment();
        // Same source name as a real JVM's environment variables: relaxed mapping applies only to it
        environment.getPropertySources().replace(
                org.springframework.core.env.StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new org.springframework.core.env.SystemEnvironmentPropertySource(
                org.springframework.core.env.StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, java.util.Map.of("SWIFTDROP_DEV_TESTTOKENS_ENABLED", "true",
                        "SWIFTDROP_JWT_ISSUER", "https://auth.swiftdrop.dev")));
        org.springframework.boot.context.properties.source.ConfigurationPropertySources.attach(environment);

        assertThatThrownBy(() -> new DevToolsSafetyCheck(environment).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class);
    }
}
