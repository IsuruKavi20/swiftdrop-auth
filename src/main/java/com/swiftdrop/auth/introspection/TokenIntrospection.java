package com.swiftdrop.auth.introspection;

import com.swiftdrop.auth.directory.ServiceClients;
import com.swiftdrop.auth.merchant.MerchantClients;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Identity step 10: "is this access token still OK right now?" (RFC 7662). Local checks (signature, issuer,
 * audience, expiry) only say the token WAS issued by us; this also checks what can change in 15 minutes: the
 * token cancelled, the person blocked or deleted, all their sessions ended, a merchant suspended. Inactive answers
 * say nothing more than {"active": false}: no reason, no hint to whoever holds the token.
 */
@Service
public class TokenIntrospection {

    private static final Map<String, Object> INACTIVE = Map.of("active", false);
    private static final String MERCHANT_CLIENT_PREFIX = "mc_";

    private final JwtDecoder decoder;
    private final RevokedAccessTokens revoked;
    private final UserRepository users;
    private final MerchantClients merchantClients;
    private final ServiceClients serviceClients;
    private final JdbcTemplate jdbc;

    TokenIntrospection(JwtDecoder decoder, RevokedAccessTokens revoked, UserRepository users,
                       MerchantClients merchantClients, ServiceClients serviceClients, JdbcTemplate jdbc) {
        this.decoder = decoder;
        this.revoked = revoked;
        this.users = users;
        this.merchantClients = merchantClients;
        this.serviceClients = serviceClients;
        this.jdbc = jdbc;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> introspect(String rawToken) {
        Optional<Jwt> decoded = decode(rawToken);
        if (decoded.isEmpty() || revoked.isRevoked(decoded.get().getId())) {
            return INACTIVE;
        }
        Jwt token = decoded.get();
        String clientId = token.getClaimAsString("client_id");
        if (ServiceClients.isServiceClientId(clientId)) {
            return serviceClients.isConfigured(clientId) ? active(token, token.getClaimAsStringList("roles"),
                    token.getClaimAsStringList("entitlements")) : INACTIVE;
        }
        if (clientId != null && clientId.startsWith(MERCHANT_CLIENT_PREFIX)) {
            return merchantStillValid(token, clientId) ? active(token, token.getClaimAsStringList("roles"),
                    token.getClaimAsStringList("entitlements")) : INACTIVE;
        }
        return personToken(token);
    }

    /** Signature, issuer, audience, at+jwt type and expiry: the same checks every protected request gets. */
    public Optional<Jwt> decode(String rawToken) {
        if (rawToken == null || rawToken.isBlank() || rawToken.length() > 8192) {
            return Optional.empty();
        }
        try {
            return Optional.of(decoder.decode(rawToken));
        } catch (JwtException notOurs) {
            return Optional.empty();
        }
    }

    // A person's token: still ACTIVE, issued after their sessions last ended; roles and permissions as they are NOW
    private Map<String, Object> personToken(Jwt token) {
        UUID userId;
        try {
            userId = UUID.fromString(token.getSubject());
        } catch (IllegalArgumentException | NullPointerException notAPerson) {
            return INACTIVE;
        }
        Optional<User> user = users.findWithRolesById(userId).filter(found -> found.getStatus() == UserStatus.ACTIVE);
        if (user.isEmpty() || issuedBeforeSessionsEnded(token, userId) || sessionEnded(token)) {
            return INACTIVE;
        }
        return active(token, user.get().roleNames(), user.get().permissionNames());
    }

    private boolean issuedBeforeSessionsEnded(Jwt token, UUID userId) {
        Timestamp validAfter = jdbc.query("SELECT tokens_valid_after FROM identity.users WHERE id = ?",
                (rs, row) -> rs.getTimestamp(1), userId).stream().filter(java.util.Objects::nonNull).findFirst()
                .orElse(null);
        // iat and tokens_valid_after are whole seconds: a token from the same second as a password change is
        // the fresh one handed out by that change
        return validAfter != null && (token.getIssuedAt() == null || token.getIssuedAt().isBefore(validAfter.toInstant()));
    }

    // The token's login session (sid) must still be open: logout or revocation of that session's refresh token
    // ends its access tokens too (RFC 7009 2.1), with no same-second gap
    private boolean sessionEnded(Jwt token) {
        String sid = token.getClaimAsString(AccessTokenIssuer.SESSION_ID_CLAIM);
        if (sid == null) {
            return false;   // tokens without a session (dev test tokens): the other checks still apply
        }
        UUID familyId;
        try {
            familyId = UUID.fromString(sid);
        } catch (IllegalArgumentException malformed) {
            return true;
        }
        return !Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM identity.refresh_tokens"
                + " WHERE family_id = ? AND revoked_at IS NULL)", Boolean.class, familyId));
    }

    private boolean merchantStillValid(Jwt token, String clientId) {
        try {
            return merchantClients.isStillValid(clientId,
                    UUID.fromString(token.getClaimAsString(AccessTokenIssuer.MERCHANT_ID_CLAIM)));
        } catch (IllegalArgumentException | NullPointerException noMerchant) {
            return false;
        }
    }

    // RFC 7662 2.2 names, plus our own roles and entitlements
    private static Map<String, Object> active(Jwt token, List<String> roles, List<String> entitlements) {
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("active", true);
        answer.put("sub", token.getSubject());
        answer.put("client_id", token.getClaimAsString("client_id"));
        answer.put("token_type", "Bearer");
        answer.put("iss", token.getClaimAsString("iss"));
        answer.put("aud", token.getAudience());
        answer.put("iat", token.getIssuedAt() == null ? null : token.getIssuedAt().getEpochSecond());
        answer.put("exp", token.getExpiresAt() == null ? null : token.getExpiresAt().getEpochSecond());
        answer.put("jti", token.getId());
        answer.put("roles", roles == null ? List.of() : roles);
        answer.put("entitlements", entitlements == null ? List.of() : entitlements);
        answer.values().removeIf(value -> value == null);
        return answer;
    }
}
