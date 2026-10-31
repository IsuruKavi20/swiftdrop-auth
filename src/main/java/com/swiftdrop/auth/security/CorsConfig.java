package com.swiftdrop.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.List;

/**
 * CORS: which OTHER websites' browser code may call this API. A browser only lets a page on
 * http://localhost:5173 read responses from us if we answer with that exact origin. Tokens travel in the
 * Authorization header, never in cookies, so credentials (cookies) are not allowed cross-site.
 */
@Configuration
class CorsConfig {

    private static final Duration PREFLIGHT_CACHE = Duration.ofHours(1);

    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties properties) {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(properties.allowedOrigins());
        cors.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        cors.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Request-Id"));
        // Let the frontend show the support reference and honour rate limits
        cors.setExposedHeaders(List.of("X-Request-Id", "Retry-After"));
        cors.setAllowCredentials(false);
        cors.setMaxAge(PREFLIGHT_CACHE);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        return source;
    }
}
