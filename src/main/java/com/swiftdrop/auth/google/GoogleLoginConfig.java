package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.web.FrontendRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/**
 * Google login, only when a Google client is configured. A SEPARATE filter chain that handles only the
 * login dance ({@code /oauth2/**}, {@code /login/oauth2/**}); everything else stays in the stateless API chain.
 */
@Configuration
@ConditionalOnExpression("'${swiftdrop.google.client-id:}' != '' and '${swiftdrop.google.client-secret:}' != ''")
class GoogleLoginConfig {

    private static final String AUTHORIZATION_PATH = "/oauth2/authorization";

    @Bean
    ClientRegistrationRepository clientRegistrationRepository(GoogleProperties google) {
        var registration = CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId(google.clientId())
                .clientSecret(google.clientSecret())
                // openid = ID token (who you are); email/profile = those claims. Nothing else is requested.
                .scope("openid", "email", "profile");
        if (google.publicBaseUrl() != null) {
            // Pinned, never built from (spoofable) Host / X-Forwarded-* headers; must match Google Cloud exactly
            registration.redirectUri(google.publicBaseUrl() + "/login/oauth2/code/{registrationId}");
        }
        return new InMemoryClientRegistrationRepository(registration.build());
    }

    @Bean
    @Order(1)
    SecurityFilterChain googleLoginChain(HttpSecurity http, ClientRegistrationRepository registrations,
                                         GoogleLoginSuccessHandler success, GoogleLoginFailureHandler failure,
                                         FrontendRegistry frontends)
            throws Exception {
        // PKCE is automatic only for public clients; we have a secret, so switch it on explicitly (RFC 9700)
        DefaultOAuth2AuthorizationRequestResolver google =
                new DefaultOAuth2AuthorizationRequestResolver(registrations, AUTHORIZATION_PATH);
        google.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        BrowserBoundAuthorizationRequestResolver requests = new BrowserBoundAuthorizationRequestResolver(google,
                frontends);

        http
                .securityMatcher(AUTHORIZATION_PATH + "/**", "/login/oauth2/**")
                .headers(headers -> headers.referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER)))
                // A short session holds state + PKCE verifier + nonce between the two redirects (ended on return)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .oauth2Login(login -> login
                        .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(requests))
                        .successHandler(success)
                        .failureHandler(failure));
        return http.build();
    }
}
