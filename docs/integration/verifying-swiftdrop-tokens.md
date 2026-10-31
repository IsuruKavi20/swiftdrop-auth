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

## 0. Microservices or one monolith: same setup
Whether SwiftDrop's other modules are separate services or one **monolith**, each application that receives requests
does the same thing: verify our tokens with our public keys (sections 2–5). For a monolith that is one application.
- Do **not** add a users/passwords table, login logic or role management to it: those live in the auth service.
- Extra per-user data (courier vehicle, customer addresses) goes in its own table **keyed by our user id (`sub`)**.
- The frontend calls the auth service for signup/login/refresh/Google, and sends the access token to the monolith.
- Not Spring? JWT + JWKS is a standard: use your platform's JOSE library (e.g. `jose` for Node.js,
  `Microsoft.IdentityModel.Tokens` for .NET) with the same checks (RS256 only, typ at+jwt, iss, aud, client_id, exp).

**Ports and browser access (dev):** the auth service runs on **9000** (your backend keeps 8080). Browser code on
`http://localhost:5173` (Vite) and `http://localhost:3000` may call it directly (CORS allow-list). In production the
allowed frontend origins are set with `SWIFTDROP_CORS_ALLOWED_ORIGINS`.

## 1. What a SwiftDrop access token contains
| Part | Value |
|---|---|
| header | `alg: RS256`, `typ: at+jwt`, `kid: <key id>` |
| `sub` | the user's ID (UUID). **Use this as the user identifier.** |
| `roles` | e.g. `["COURIER"]` (CUSTOMER, MERCHANT, COURIER, DISPATCHER, ADMIN) |
| `entitlements` | the permissions those roles grant, e.g. `["delivery:read-own","delivery:update-status"]` (table below) |
| `iss` | the auth service URL (dev: `http://localhost:9000`) |
| `aud` | `swiftdrop-api` |
| `client_id` | `swiftdrop-web` |
| `exp` / `iat` / `jti` | expiry (15 min after issue), issue time, unique token ID |
There is **no email or name** in the token by design.

### Permissions per role (draft vocabulary: tell the auth team before adding one)
| Role | Entitlements |
|---|---|
| CUSTOMER | `parcel:create`, `parcel:read-own` |
| MERCHANT | `parcel:create`, `parcel:read-own`, `merchant:api-access` |
| COURIER | `delivery:read-own`, `delivery:update-status` |
| DISPATCHER | `parcel:read-all`, `parcel:assign`, `delivery:read-all` |
| ADMIN | `parcel:read-all`, `parcel:assign`, `delivery:read-all`, `merchant:approve`, `user:read`, `user:manage-roles`, `audit:read` |

**Check permissions, not role names** (`hasAuthority("parcel:assign")`, not `hasRole("DISPATCHER")`): if the
mapping changes, your code does not. Role changes apply from the user's next login (tokens live 15 minutes).

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
    issuer: http://localhost:9000                                   # must match the token's "iss" exactly
    jwk-set-uri: http://localhost:9000/.well-known/jwks.json
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
        // client_id: our user apps (swiftdrop-web) OR a merchant's software (mc_ + 22 chars), nothing else
        OAuth2TokenValidator<Jwt> knownClient = new JwtClaimValidator<String>("client_id",
                id -> clientId.equals(id) || (id != null && id.matches("^mc_[A-Za-z0-9_-]{22}$")));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createAtJwtValidator()                     // typ at+jwt, iss, aud, exp, required claims
                        .issuer(issuer).audience(audience).build(),
                knownClient));
        return decoder;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("roles");          // ["COURIER"] → ROLE_COURIER
        roles.setAuthorityPrefix("ROLE_");
        JwtGrantedAuthoritiesConverter entitlements = new JwtGrantedAuthoritiesConverter();
        entitlements.setAuthoritiesClaimName("entitlements");  // ["delivery:read-own"] → delivery:read-own
        entitlements.setAuthorityPrefix("");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> all = new ArrayList<>(roles.convert(jwt));
            all.addAll(entitlements.convert(jwt));
            return all;
        });

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

When the owner's ID IS in the URL (e.g. a dispatcher screen), use the ownership pattern with method security
(`@EnableMethodSecurity` on your config):
```java
@GetMapping("/api/v1/couriers/{courierId}/deliveries")
@PreAuthorize("#courierId.toString() == authentication.name or hasAuthority('delivery:read-all')")
List<DeliveryDto> deliveriesOf(@PathVariable UUID courierId) { ... }
```
The courier gets their own list; another courier's ID → 403; a dispatcher (`delivery:read-all`) sees any.
(The auth service wraps this as `@RequireOwnerOrPermission(owner = "#courierId", permission = "delivery:read-all")`;
it moves to the shared library in Step 18.)

## 6. Testing without the auth service running
```java
mockMvc.perform(get("/api/v1/deliveries/mine")
        .with(jwt().jwt(j -> j.subject(courierId.toString()).claim("roles", List.of("COURIER")))
                   .authorities(new SimpleGrantedAuthority("ROLE_COURIER"),
                                new SimpleGrantedAuthority("delivery:read-own"))))
       .andExpect(status().isOk());
```
(`spring-security-test`; `jwt()` from `SecurityMockMvcRequestPostProcessors`.) For real tokens in local runs,
log in at `POST /api/v1/auth/login`. A dev test-token endpoint is coming (Step 9).

## 6b. Getting a real token instantly (development only)
Run the auth service locally (`docker compose up -d`, then `.\mvnw spring-boot:run`) and ask for any role:
```bash
curl -X POST http://localhost:9000/api/v1/dev/test-tokens \
     -H "Content-Type: application/json" \
     -d '{"roles":["COURIER"],"userId":"11111111-1111-1111-1111-111111111111"}'
# → {"access_token":"eyJ...","token_type":"Bearer","expires_in":900}
```
- `roles`: 1–5 of CUSTOMER, MERCHANT, COURIER, DISPATCHER, ADMIN. `userId` is optional (random if missing).
- Use two fixed IDs for the **courier-isolation test**: courier A `1111…`, courier B `2222…`. A's token must not
  return B's deliveries.
- The token is real (signed with the dev key, valid 15 min) and carries `"test_token": true`.
- It **only exists on a developer's machine**: dev profile AND a `localhost` issuer, otherwise the auth service
  refuses to start. Never build features that depend on it.
- **Your service MUST reject test tokens outside development.** Add this validator in deployed profiles (it complements
  the issuer/key checks, which already differ between dev and production):
  ```java
  OAuth2TokenValidator<Jwt> noTestTokens = jwt -> Boolean.TRUE.equals(jwt.getClaim("test_token"))
          ? OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "test tokens not accepted", null))
          : OAuth2TokenValidatorResult.success();
  decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(atJwtValidator, noTestTokens));
  ```
- **Never deploy the `dev` profile** (not even to staging): deployed environments get their own profile.

## 6c. For the frontend / mobile team: staying logged in
Login returns two tokens:
```json
{"access_token":"eyJ...","token_type":"Bearer","expires_in":900,
 "refresh_token":"Xy3...43 chars","refresh_expires_in":86400}
```
- Send `access_token` as `Authorization: Bearer ...` to every service. When it expires (or a service answers 401),
  call `POST /api/v1/auth/refresh` with `{"refresh_token":"..."}`. You get **both tokens new**; always keep the new
  refresh token, because the old one is now dead.
- **Refresh one at a time** (one shared promise or lock across tabs/requests). Sending the same refresh token twice
  looks like theft: the whole session is ended and the user must log in again.
- `401 INVALID_REFRESH_TOKEN` means the session is over (1 day unused, 7 days since login, logout, role removed,
  or account disabled), so send the user to the login screen.
- Logout: `POST /api/v1/auth/logout` with `{"refresh_token":"..."}` → always `204`; then forget both tokens.
- Web: keep the refresh token in memory, **never in localStorage** (any XSS could read it). Mobile: Keychain /
  Android Keystore-backed storage.

## 6d. For the frontend team: "Continue with Google"
1. Before leaving, make a **verifier** and its **challenge** (this proves later that the code came back to the SAME
   browser; without it an attacker could log you into *their* account):
   ```js
   const bytes = crypto.getRandomValues(new Uint8Array(32));
   const verifier = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
   const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
   const challenge = btoa(String.fromCharCode(...hash)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
   sessionStorage.setItem("google_verifier", verifier);
   location.href = "http://localhost:9000/oauth2/authorization/google?code_challenge=" + challenge;
   ```
   (full page navigation, not fetch/XHR)
2. After Google, the user lands on **your** page `/auth/callback` with either
   `#code=<43 chars>` or `#error=login_failed` in the URL fragment (never sent to any server).
   **Immediately** remove it from the address bar: `history.replaceState(null, "", "/auth/callback")`.
   The callback page must load no third-party scripts.
3. Within 60 seconds: `POST /api/v1/auth/google/exchange` with
   `{"code":"...","verifier":sessionStorage.getItem("google_verifier")}` → the same token response as login
   (`access_token`, `refresh_token`, ...). The code works **once** (even a wrong verifier burns it). Then delete the
   verifier from sessionStorage.
4. `#error=login_failed` or a `401 INVALID_LOGIN_CODE`: show "Google sign-in failed, please try again".
Google users are normal SwiftDrop users: same tokens, same roles (from our database, never from Google).

## 6e. Merchant systems (machine-to-machine tokens)
An approved merchant's software gets tokens with the OAuth 2.0 **client credentials** grant:
```bash
curl -u "mc_xxxxxxxxxxxxxxxxxxxxxx:<client secret>" -d grant_type=client_credentials http://localhost:9000/oauth2/token
# → {"access_token":"eyJ...","token_type":"Bearer","expires_in":900}   (no refresh token: just ask again)
```
Its token has **no user**:
| Claim | Value |
|---|---|
| `sub`, `client_id` | `mc_…` (the merchant's API client) |
| `merchant_id` | the merchant (UUID): **use this** to scope data to the merchant |
| `roles` / `entitlements` | `["MERCHANT"]` / `merchant:api-access`, `parcel:create`, `parcel:read-own` |
So in your code: `sub` is a UUID for people, `mc_…` for merchant machines. For merchant data, filter by
`token.getClaimAsString("merchant_id")`, never by a value from the request. Merchant (people) accounts apply and get
approved through the auth service (`POST /api/v1/merchants/application`, admin `POST /api/v1/admin/merchants/{id}/decision`).

## 6f. Rate limits you may hit
Public auth endpoints are limited per client IP (e.g. login 10/min, signup 5/min, `/oauth2/token` 30/min) and answer
`429 RATE_LIMITED` with `Retry-After: <seconds>`. Wait that long; don't retry in a loop.

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
