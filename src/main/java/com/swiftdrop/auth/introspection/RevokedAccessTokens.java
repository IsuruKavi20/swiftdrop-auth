package com.swiftdrop.auth.introspection;

import com.swiftdrop.auth.session.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Clock;

/**
 * Identity step 10: token revocation (RFC 7009). A refresh token ends that session (as logout); an access token's
 * id (jti) goes on a small list that introspection checks. A list entry is useless once the token has expired
 * anyway, so the nightly clean-up keeps the list tiny (at most 15 minutes of logouts).
 */
@Service
public class RevokedAccessTokens {

    private static final Logger log = LoggerFactory.getLogger(RevokedAccessTokens.class);
    private static final int MAX_JTI = 64;

    private final JdbcTemplate jdbc;
    private final SessionService sessions;
    private final Clock clock;

    RevokedAccessTokens(JdbcTemplate jdbc, SessionService sessions, Clock clock) {
        this.jdbc = jdbc;
        this.sessions = sessions;
        this.clock = clock;
    }

    boolean isRevoked(String jti) {
        return jti == null || Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM identity.revoked_access_tokens WHERE jti = ?)", Boolean.class, jti));
    }

    /** A valid access token of ours (already decoded): cancel it. Repeats are fine. */
    @Transactional
    public void revokeAccessToken(Jwt token) {
        if (token.getId() == null || token.getId().length() > MAX_JTI || token.getExpiresAt() == null) {
            return;
        }
        jdbc.update("INSERT INTO identity.revoked_access_tokens (jti, expires_at) VALUES (?, ?)"
                + " ON CONFLICT (jti) DO NOTHING", token.getId(), Timestamp.from(token.getExpiresAt()));
        log.info("Access token revoked jti={}", token.getId());
    }

    /** Anything else is tried as a refresh token: ends that session, silently for unknown values. */
    public void revokeRefreshToken(String rawToken) {
        sessions.logout(rawToken);
    }

    @Scheduled(cron = "${swiftdrop.introspection.cleanup-cron:0 50 3 * * *}")
    @Transactional
    public int removeExpired() {
        int removed = jdbc.update("DELETE FROM identity.revoked_access_tokens WHERE expires_at < ?",
                Timestamp.from(clock.instant()));
        if (removed > 0) {
            log.info("Revoked access tokens cleaned up count={}", removed);
        }
        return removed;
    }
}
