package com.swiftdrop.auth.security;

import jakarta.servlet.DispatcherType;
import com.swiftdrop.auth.common.web.ApiPaths;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.SecurityFilterChain;

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
                        // API docs: only exist when springdoc is enabled (dev); elsewhere these paths are 404
                        .requestMatchers("/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**")
                        .permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }
}
