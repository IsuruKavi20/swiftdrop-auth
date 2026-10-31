package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import com.swiftdrop.auth.session.InvalidRefreshTokenException;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.session.SessionTokens;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * One-time hand-off codes: our tokens never travel in a redirect URL. After Google login the browser gets
 * a 60-second code in the URL fragment and swaps it (POST) for tokens. Only the hash is stored.
 */
@Service
public class HandoffCodes {

    private static final Duration TTL = Duration.ofSeconds(60);
    private static final Duration KEEP_AFTER_EXPIRY = Duration.ofDays(1);

    private final HandoffCodeRepository codes;
    private final UserRepository users;
    private final SessionService sessions;
    private final Clock clock;

    HandoffCodes(HandoffCodeRepository codes, UserRepository users, SessionService sessions, Clock clock) {
        this.codes = codes;
        this.users = users;
        this.sessions = sessions;
        this.clock = clock;
    }

    /** @param browserChallenge base64url(SHA-256(verifier)) sent by the browser that started the login */
    @Transactional
    public String issue(UUID userId, String browserChallenge) {
        String code = OpaqueTokens.newToken();
        Instant now = clock.instant();
        codes.save(new HandoffCode(userId, OpaqueTokens.hash(code), browserChallenge, now, now.plus(TTL)));
        return code;
    }

    // A used code must stay used even when we answer 401, so these exceptions do not roll back.
    // Lock order: code row (consume), then user row (sessions.start). Nothing locks them the other way round.
    @Transactional(noRollbackFor = {InvalidLoginCodeException.class, InvalidRefreshTokenException.class})
    public SessionTokens redeem(String rawCode, String verifier) {
        if (!OpaqueTokens.isWellFormed(rawCode) || !OpaqueTokens.isWellFormed(verifier)) {
            throw new InvalidLoginCodeException();
        }
        Instant now = clock.instant();
        HandoffCode code = codes.findByCodeHash(OpaqueTokens.hash(rawCode)).orElseThrow(InvalidLoginCodeException::new);
        // Burn first: a code tried with the wrong verifier (an injected one) is dead afterwards too
        if (codes.consumeIfUsable(code.getId(), now) != 1
                || !OpaqueTokens.matches(code.getBrowserChallenge(), OpaqueTokens.s256(verifier))) {
            throw new InvalidLoginCodeException();
        }
        User user = users.findWithRolesById(code.getUserId())
                .filter(found -> found.isUsable() && found.isEmailVerified())
                .orElseThrow(InvalidLoginCodeException::new);
        return sessions.start(user);
    }

    @Scheduled(cron = "${swiftdrop.google.cleanup-cron:0 45 3 * * *}")
    @Transactional
    public void deleteExpiredCodes() {
        codes.deleteExpiredBefore(clock.instant().minus(KEEP_AFTER_EXPIRY));
    }
}
