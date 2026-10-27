package com.swiftdrop.auth.token;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Set;

/**
 * Guard for the test-token endpoint. It exists in EVERY environment (unlike the endpoint) and the endpoint
 * depends on it, so it always runs first. With test tokens switched on, startup is refused unless this is
 * clearly a developer's machine:
 * <ul>
 *   <li>never together with the prod profile;</li>
 *   <li>POSITIVE check: the token issuer must be localhost. Any real deployment (staging, production, a
 *       server someone started with the dev profile by mistake, a profile named "production") has a real
 *       issuer URL, so it fails here whatever its profiles are called.</li>
 * </ul>
 */
@Component
public class DevToolsSafetyCheck implements InitializingBean {

    static final String TEST_TOKENS_ENABLED = "swiftdrop.dev.test-tokens.enabled";
    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");

    private final Environment environment;

    DevToolsSafetyCheck(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void afterPropertiesSet() {
        boolean enabled = environment.getProperty(TEST_TOKENS_ENABLED, Boolean.class, false);
        if (!enabled) {
            return;
        }
        if (environment.matchesProfiles("prod")) {
            throw new IllegalStateException(TEST_TOKENS_ENABLED + "=true is never allowed with the prod profile "
                    + "(swiftdrop.dev.test-tokens hands out tokens for any role without a login)");
        }
        String issuer = environment.getProperty("swiftdrop.jwt.issuer", "");
        if (!isLocalhost(issuer)) {
            throw new IllegalStateException(TEST_TOKENS_ENABLED + "=true is only allowed on a developer's machine "
                    + "(swiftdrop.jwt.issuer must be localhost, but is '" + issuer + "'). "
                    + "The dev profile must never be deployed; give deployed environments their own profile.");
        }
    }

    private static boolean isLocalhost(String issuer) {
        try {
            String host = URI.create(issuer).getHost();
            return host != null && LOCAL_HOSTS.contains(host);
        } catch (IllegalArgumentException notAUri) {
            return false;
        }
    }
}
