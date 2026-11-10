package com.swiftdrop.auth.security;

import jakarta.servlet.DispatcherType;
import com.swiftdrop.auth.common.web.ApiPaths;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
// Turns on @PreAuthorize and our own @RequireRole / @RequirePermission / @RequireOwnerOrPermission
@EnableMethodSecurity
public class SecurityConfig {

    // Lets our annotations fill {placeholders} in their @PreAuthorize template (static: needed very early)
    @Bean
    static AnnotationTemplateExpressionDefaults annotationTemplateDefaults() {
        return new AnnotationTemplateExpressionDefaults();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            ProblemDetailsAuthenticationEntryPoint authenticationEntryPoint,
                                            ProblemDetailsAccessDeniedHandler accessDeniedHandler) throws Exception {
        http
                // Bearer-token API, not cookie sessions, so CSRF does not apply here (plan section 16)
                .csrf(csrf -> csrf.disable())
                // Browser calls from our allow-listed frontends only (CorsConfig); preflights are answered here
                .cors(Customizer.withDefaults())
                // Never leak URLs (which may carry tokens) to other sites through the Referer header
                .headers(headers -> headers.referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER)))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                // Protected endpoints accept "Authorization: Bearer <access token>", verified by the JwtDecoder bean
                // (RS256, at+jwt, issuer, audience, client_id, expiry). Bad tokens get the same 401 Problem Details.
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .bearerTokenResolver(ignoringPublicEndpoints())
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(authoritiesFromTokens())))
                .authorizeHttpRequests(auth -> auth
                        // Error dispatches render our Problem Details error page, never protected content
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.POST, ApiPaths.AUTH + "/signup", ApiPaths.AUTH + "/login")
                        .permitAll()
                        // The refresh token in the body IS the credential here (no access token needed)
                        .requestMatchers(HttpMethod.POST, ApiPaths.AUTH + "/refresh", ApiPaths.AUTH + "/logout")
                        .permitAll()
                        // Google login's last step: the one-time code in the body is the credential
                        .requestMatchers(HttpMethod.POST, ApiPaths.AUTH + "/google/exchange").permitAll()
                        // Email change links: the one-time token in the body is the credential (step 3b)
                        .requestMatchers(HttpMethod.POST, ApiPaths.AUTH + "/email-change/confirm",
                                ApiPaths.AUTH + "/email-change/revert").permitAll()
                        // OAuth token endpoint for merchants' software: client id + secret (HTTP Basic) are the credential
                        .requestMatchers(HttpMethod.POST, "/oauth2/token").permitAll()
                        // Step 10: introspect checks its caller itself (service client Basic auth); revoke needs
                        // only the token being cancelled (RFC 7009)
                        .requestMatchers(HttpMethod.POST, "/oauth2/introspect", "/oauth2/revoke").permitAll()
                        // Any method is let through so a GET gets an honest 405, not a misleading 401
                        .requestMatchers(ApiPaths.AUTH + "/email-verification", ApiPaths.AUTH + "/email-verification/resend")
                        .permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // Dev-only test tokens: this path only has a handler when DevTestTokenController exists
                        .requestMatchers(HttpMethod.POST, ApiPaths.V1 + "/dev/test-tokens").permitAll()
                        // Our public key set: other services download it to verify tokens
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json", "/.well-known/openid-configuration")
                        .permitAll()
                        // API docs: only exist when springdoc is enabled (dev); elsewhere these paths are 404
                        .requestMatchers("/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**")
                        .permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }

    // Public endpoints never look at a Bearer header: a client holding an expired token must still be able
    // to log in, sign up or verify its email (otherwise the stale token would cause a 401 there)
    private static BearerTokenResolver ignoringPublicEndpoints() {
        RequestMatcher publicEndpoints = new OrRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/signup"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/login"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/refresh"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/logout"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/google/exchange"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/email-change/**"),
                PathPatternRequestMatcher.withDefaults().matcher("/oauth2/token"),
                PathPatternRequestMatcher.withDefaults().matcher("/oauth2/introspect"),
                PathPatternRequestMatcher.withDefaults().matcher("/oauth2/revoke"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/email-verification/**"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/email-verification"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.V1 + "/dev/test-tokens"),
                PathPatternRequestMatcher.withDefaults().matcher("/.well-known/**"),
                PathPatternRequestMatcher.withDefaults().matcher("/actuator/health/**"));
        DefaultBearerTokenResolver standard = new DefaultBearerTokenResolver();
        return request -> publicEndpoints.matches(request) ? null : standard.resolve(request);
    }

    // Token claims become Spring authorities:
    //   "roles": ["COURIER"]                   -> ROLE_COURIER       (for hasRole("COURIER"))
    //   "entitlements": ["delivery:read-own"]  -> delivery:read-own  (for hasAuthority("delivery:read-own"))
    private static JwtAuthenticationConverter authoritiesFromTokens() {
        Converter<Jwt, Collection<GrantedAuthority>> roles = claimToAuthorities("roles", "ROLE_");
        Converter<Jwt, Collection<GrantedAuthority>> entitlements = claimToAuthorities("entitlements", "");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> all = new ArrayList<>(roles.convert(jwt));
            all.addAll(entitlements.convert(jwt));
            return all;
        });
        return converter;
    }

    private static JwtGrantedAuthoritiesConverter claimToAuthorities(String claim, String prefix) {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(claim);
        authorities.setAuthorityPrefix(prefix);
        return authorities;
    }
}
