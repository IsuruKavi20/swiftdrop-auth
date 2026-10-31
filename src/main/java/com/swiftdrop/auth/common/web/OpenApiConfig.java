package com.swiftdrop.auth.common.web;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/**
 * The machine-readable API contract (/v3/api-docs) and Swagger UI for teammates. Only switched on in the
 * dev profile (springdoc.*.enabled), so production exposes no API map. "bearerAuth" describes how
 * protected endpoints will be called once login issues JWTs (Step 7).
 */
@Configuration
@OpenAPIDefinition(info = @Info(
        title = "SwiftDrop Identity & Auth Service",
        version = "v1",
        description = "Signup, email verification and (coming next) login and tokens. "
                + "Every error is RFC 9457 Problem Details with a 'code' and 'requestId'."))
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT")
public class OpenApiConfig {
}
