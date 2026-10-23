package com.swiftdrop.auth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.web.client.RestClient;

import java.time.Duration;

/** Wires the breached-password check (Have I Been Pwned) or, outside production only, a disabled stand-in. */
@Configuration
public class BreachedPasswordCheckConfig {

    public static final String USER_AGENT = "swiftdrop-auth";
    static final String API_URL = "https://api.pwnedpasswords.com/range/";
    private static final String ENABLED = "swiftdrop.security.breached-password-check.enabled";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(3);
    // Total time a signup waits for the lookup, whatever the network does (slow drip, DNS, ...)
    private static final Duration TOTAL_DEADLINE = Duration.ofSeconds(3);

    private static final Logger log = LoggerFactory.getLogger(BreachedPasswordCheckConfig.class);

    @Bean
    @ConditionalOnBooleanProperty(name = ENABLED, matchIfMissing = true)
    CompromisedPasswordChecker haveIBeenPwnedChecker() {
        return new HaveIBeenPwnedClient(hibpClientBuilder().build(), TOTAL_DEADLINE);
    }

    /** Tests and offline development never call the internet. Production refuses to start like this. */
    @Bean
    @ConditionalOnBooleanProperty(name = ENABLED, havingValue = false)
    CompromisedPasswordChecker breachCheckDisabled(Environment environment) {
        if (environment.matchesProfiles("prod")) {
            throw new IllegalStateException(ENABLED + "=false is not allowed with the prod profile");
        }
        log.warn("Breached-password check is DISABLED ({}=false). Never run like this in production.", ENABLED);
        return password -> new CompromisedPasswordDecision(false);
    }

    static RestClient.Builder hibpClientBuilder() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(CONNECT_TIMEOUT);
        requestFactory.setReadTimeout(READ_TIMEOUT);
        return RestClient.builder()
                .baseUrl(API_URL)
                .requestFactory(requestFactory)
                // Pads responses to 800-1,000 rows so their size doesn't hint at the password
                .defaultHeader("Add-Padding", "true")
                .defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT);
    }
}
