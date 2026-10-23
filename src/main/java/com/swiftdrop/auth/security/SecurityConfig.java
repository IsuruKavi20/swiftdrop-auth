package com.swiftdrop.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Map;

@Configuration
public class SecurityConfig {

    // Stored hashes look like "{argon2}$argon2id$...": the id lets us change algorithm later
    // while still verifying old hashes.
    private static final String CURRENT_ENCODER_ID = "argon2";

    @Bean
    PasswordEncoder passwordEncoder(PasswordHashingProperties settings) {
        PasswordEncoder argon2 = new Argon2PasswordEncoder(
                settings.saltLengthBytes(), settings.hashLengthBytes(), settings.parallelism(),
                settings.memoryKb(), settings.iterations());
        return new DelegatingPasswordEncoder(CURRENT_ENCODER_ID, Map.of(CURRENT_ENCODER_ID, argon2));
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Bearer-token API, not cookie sessions, so CSRF does not apply here (plan section 16)
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/signup").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }
}
