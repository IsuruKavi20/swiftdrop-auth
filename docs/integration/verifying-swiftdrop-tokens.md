# Verifying SwiftDrop access tokens in your service

For every SwiftDrop service that needs to know **who is calling** (parcels, dispatch, merchant, ...).
Your service never sees passwords and never calls the auth service per request: it checks the token's
**signature** with the auth service's **public key** and reads the user ID and roles from it.

```
Client ──Authorization: Bearer <access token>──► your service
                                                    │ 1. verify signature with the auth service's public key
                                                    │    (downloaded once from /.well-known/jwks.json, cached 5 min)
                                                    │ 2. check typ, issuer, audience, client_id, expiry
                                                    ▼ 3. user ID = "sub", roles = "roles" → ROLE_COURIER, ...
```

## 1. What a SwiftDrop access token contains
| Part | Value |
|---|---|
| header | `alg: RS256`, `typ: at+jwt`, `kid: <key id>` |
| `sub` | the user's ID (UUID). **Use this as the user identifier.** |
| `roles` | e.g. `["COURIER"]` (CUSTOMER, MERCHANT, COURIER, DISPATCHER, ADMIN) |
| `iss` | the auth service URL (dev: `http://localhost:8080`) |
| `aud` | `swiftdrop-api` |
| `client_id` | `swiftdrop-web` |
| `exp` / `iat` / `jti` | expiry (15 min after issue), issue time, unique token ID |
There is **no email or name** in the token by design.

## 2. Add the dependency (Spring Boot 4)
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security-oauth2-resource-server</artifactId>
</dependency>
```

## 3. Configure (`application.yml`)
```yaml
swiftdrop:
  auth:
    issuer: http://localhost:8080                                   # must match the token's "iss" exactly
    jwk-set-uri: http://localhost:8080/.well-known/jwks.json
    audience: swiftdrop-api
    client-id: swiftdrop-web
```
(Production: the real auth service URL, e.g. `https://auth.swiftdrop.dev`.)

## 4. Security configuration (copy into your service)
```java
@Configuration
public class SecurityConfig {

    @Bean
    JwtDecoder jwtDecoder(@Value("${swiftdrop.auth.jwk-set-uri}") String jwkSetUri,
                          @Value("${swiftdrop.auth.issuer}") String issuer,
                          @Value("${swiftdrop.auth.audience}") String audience,
                          @Value("${swiftdrop.auth.client-id}") String clientId) {
        // RS256 only; typ checking is done by the RFC 9068 validator below
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .validateType(false)   // Spring Security 7.1.x name (some docs say validateTypes)
                .build();
        decoder.setJwtValidator(JwtValidators.createAtJwtValidator()   // typ at+jwt, iss, aud, client_id, exp
                .issuer(issuer).audience(audience).clientId(clientId)
                .build());
        return decoder;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("roles");   // ["COURIER"] → ROLE_COURIER
        roles.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(roles);

        http.csrf(csrf -> csrf.disable())          // bearer tokens in headers, no cookies
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/api/v1/deliveries/**").hasAnyRole("COURIER", "DISPATCHER")
                .anyRequest().authenticated())
            .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)));
        return http.build();
    }
}
```
Verified against Spring Security **7.1.1**: the builder method is `validateType(false)`. `createAtJwtValidator()`
is what checks `typ: at+jwt`, issuer, audience, client_id, expiry and required claims.
**Never replace it with `JwtValidators.createDefault()`**: that skips the audience/client_id/typ checks.
**Only trust `roles` from tokens whose issuer is the SwiftDrop auth service** (the validator guarantees this).

## 5. Use the caller in your code
```java
@GetMapping("/api/v1/deliveries/mine")
List<DeliveryDto> myDeliveries(@AuthenticationPrincipal Jwt token) {
    UUID courierId = UUID.fromString(token.getSubject());   // ALWAYS take the ID from the token,
    return deliveries.findForCourier(courierId);            // never from a request parameter
}
```
**Required brief test:** a courier must not see another courier's deliveries. Filter by `token.getSubject()`
and test it with two different courier tokens.

## 6. Testing without the auth service running
```java
mockMvc.perform(get("/api/v1/deliveries/mine")
        .with(jwt().jwt(j -> j.subject(courierId.toString()).claim("roles", List.of("COURIER")))
                   .authorities(new SimpleGrantedAuthority("ROLE_COURIER"))))
       .andExpect(status().isOk());
```
(`spring-security-test`; `jwt()` from `SecurityMockMvcRequestPostProcessors`.) For real tokens in local runs,
log in at `POST /api/v1/auth/login`. A dev test-token endpoint is coming (Step 9).

## 7. Key rotation: nothing to do
When the auth service rotates, the new key appears in the JWKS and signs new tokens from the same moment; the old
public key stays published for ≥ 24 h so older tokens still verify. Spring's `jwk-set-uri` decoder caches the set
for 5 minutes and **re-fetches when it sees an unknown `kid`**, so new tokens work immediately.
- **Never hard-code the public key** and don't add your own long-lived cache in front of `jwk-set-uri`.
- After a **key compromise** the old key is removed at once: tokens it signed stop working immediately (by design).
- If you ever build a deny-list or cache keyed on a token, key it on the `jti` claim, **never on the raw token
  string** (base64url lets one token be written in more than one way).

## 8. Error responses you should expect
`401` (missing/invalid/expired token) and `403` (valid token, wrong role). The auth service returns RFC 9457 Problem
Details JSON; your service's own 401/403 format is up to you (ideally the same shape).
