package com.swiftdrop.auth.session;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import com.swiftdrop.auth.user.IdentityEvents;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.IdTokenIssuer;
import com.swiftdrop.auth.token.IdentityClaims;
import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.token.PersonClaims;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Sessions = refresh-token families. Login starts one; every refresh swaps the token for a new one
 * (rotation); an already-used token coming back means a copy exists, so the whole family is revoked.
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final RefreshTokenRepository tokens;
    private final UserRepository users;
    private final AccessTokenIssuer accessTokens;
    private final IdTokenIssuer idTokens;
    private final SessionProperties properties;
    private final Clock clock;

    private final IdentityEvents identityEvents;

    SessionService(RefreshTokenRepository tokens, UserRepository users, AccessTokenIssuer accessTokens,
                   IdTokenIssuer idTokens, SessionProperties properties, Clock clock, IdentityEvents identityEvents) {
        this.tokens = tokens;
        this.users = users;
        this.accessTokens = accessTokens;
        this.idTokens = idTokens;
        this.properties = properties;
        this.clock = clock;
        this.identityEvents = identityEvents;
    }

    /**
     * After a successful login. The user row is locked and re-read, so the token gets the roles as they are NOW
     * (a role revoke running at the same moment either finishes first or waits for this session, then ends it).
     * The account checks run again on that fresh row: an admin who disabled it after the caller's check wins.
     */
    @Transactional
    public SessionTokens start(User user) {
        Instant now = clock.instant();
        User current = users.lockById(user.getId()).orElseThrow(InvalidRefreshTokenException::new);
        if (current.getStatus() != UserStatus.ACTIVE || !current.isEmailVerified()) {
            throw new InvalidRefreshTokenException();
        }
        return issue(current, UUID.randomUUID(), now.plus(properties.absoluteTimeout()), now);
    }

    // Revocations must survive the 401, so this exception does not roll the transaction back
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public SessionTokens refresh(String rawToken) {
        if (!OpaqueTokens.isWellFormed(rawToken)) {
            throw new InvalidRefreshTokenException();
        }
        Instant now = clock.instant();
        String hash = OpaqueTokens.hash(rawToken);
        // Lock order: user row first, then the token row (same order as role revoke: no deadlock, no missed token)
        UUID userId = tokens.findUserIdByHash(hash).orElseThrow(InvalidRefreshTokenException::new);
        User user = users.lockById(userId).orElseThrow(InvalidRefreshTokenException::new);
        RefreshToken current = tokens.lockByHash(hash).orElseThrow(InvalidRefreshTokenException::new);
        if (current.isRevoked()) {
            throw new InvalidRefreshTokenException();
        }
        if (current.isUsed()) {
            tokens.revokeFamily(current.getFamilyId(), RevokeReason.REUSE_DETECTED, now);
            log.warn("Refresh token reuse detected, session revoked: user={} family={}",
                    current.getUserId(), current.getFamilyId());
            throw new InvalidRefreshTokenException();
        }
        if (current.isExpiredAt(now)) {
            throw new InvalidRefreshTokenException();
        }
        // Fresh from the database: a disabled account stops here, and role changes reach the next token
        if (user.getStatus() != UserStatus.ACTIVE || !user.isEmailVerified()) {
            tokens.revokeFamily(current.getFamilyId(), RevokeReason.ACCOUNT_DISABLED, now);
            throw new InvalidRefreshTokenException();
        }
        // A temporary failed-password lock does NOT stop refresh: it guards password guessing only (Step 14)
        current.markUsed(now);
        tokens.flush();   // the old token is used BEFORE the new one exists (one live token per family)
        return issue(user, current.getFamilyId(), current.getFamilyExpiresAt(), now);
    }

    /** Ends this device's session. Silent for unknown tokens, so logout reveals nothing. */
    @Transactional
    public void logout(String rawToken) {
        if (!OpaqueTokens.isWellFormed(rawToken)) {
            return;
        }
        // Locked, so a refresh running at this moment finishes first and its new token is revoked too
        tokens.lockByHash(OpaqueTokens.hash(rawToken))
                .ifPresent(token -> tokens.revokeFamily(token.getFamilyId(), RevokeReason.LOGOUT, clock.instant()));
    }

    /** Ends every session of the user (role removed; later: password reset, MFA change). */
    @Transactional
    public void endAllSessions(UUID userId, RevokeReason reason) {
        int revoked = tokens.revokeAllForUser(userId, reason, clock.instant());
        identityEvents.sessionsRevoked(userId, reason.name());
        log.info("All sessions ended: user={} reason={} tokens={}", userId, reason, revoked);
    }

    private SessionTokens issue(User user, UUID familyId, Instant familyExpiresAt, Instant now) {
        String refreshToken = OpaqueTokens.newToken();
        Instant idleLimit = now.plus(properties.idleTimeout());
        Instant expiresAt = idleLimit.isBefore(familyExpiresAt) ? idleLimit : familyExpiresAt;
        tokens.save(new RefreshToken(user.getId(), familyId, OpaqueTokens.hash(refreshToken), now, expiresAt,
                familyExpiresAt));
        // Identity claims come from the user row read for this login/refresh: a changed name shows up next refresh
        PersonClaims person = new PersonClaims(user.getEmail(), user.isEmailVerified(), user.getName());
        IssuedToken access = accessTokens.issue(user.getId(), person, user.roleNames(), user.permissionNames());
        String idToken = idTokens.issue(user.getId(), new IdentityClaims(user.getEmail(), user.isEmailVerified(),
                user.getName(), user.getGivenName(), user.getFamilyName(), user.getPictureUrl(), user.getLocale(),
                user.getProfileUpdatedAt()));
        return new SessionTokens(access, refreshToken, Duration.between(now, expiresAt), idToken);
    }
}
