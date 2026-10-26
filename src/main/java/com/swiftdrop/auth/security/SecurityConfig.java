package com.swiftdrop.auth.security;

import jakarta.servlet.DispatcherType;
import com.swiftdrop.auth.common.web.ApiPaths;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            ProblemDetailsAuthenticationEntryPoint authenticationEntryPoint,
                                            ProblemDetailsAccessDeniedHandler accessDeniedHandler) throws Exception {
        http
                // Bearer-token API, not cookie sessions, so CSRF does not apply here (plan section 16)
                .csrf(csrf -> csrf.disable())
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
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(rolesFromTokens())))
                .authorizeHttpRequests(auth -> auth
                        // Error dispatches render our Problem Details error page, never protected content
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.POST, ApiPaths.AUTH + "/signup", ApiPaths.AUTH + "/login")
                        .permitAll()
                        // Any method is let through so a GET gets an honest 405, not a misleading 401
                        .requestMatchers(ApiPaths.AUTH + "/email-verification", ApiPaths.AUTH + "/email-verification/resend")
                        .permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // Our public key set: other services download it to verify tokens
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
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
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/email-verification/**"),
                PathPatternRequestMatcher.withDefaults().matcher(ApiPaths.AUTH + "/email-verification"),
                PathPatternRequestMatcher.withDefaults().matcher("/.well-known/**"),
                PathPatternRequestMatcher.withDefaults().matcher("/actuator/health/**"));
        DefaultBearerTokenResolver standard = new DefaultBearerTokenResolver();
        return request -> publicEndpoints.matches(request) ? null : standard.resolve(request);
    }

    // The token's "roles" claim (["COURIER"]) becomes Spring authorities ROLE_COURIER, for hasRole("COURIER")
    private static JwtAuthenticationConverter rolesFromTokens() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("roles");
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }
}
