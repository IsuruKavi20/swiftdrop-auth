package com.swiftdrop.auth.verification;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class VerificationTokenCleanupTest {

    @Test
    void deletesTokensThatExpiredMoreThanADayAgo() {
        Instant now = Instant.parse("2026-10-24T03:00:00Z");
        VerificationTokenRepository tokens = mock(VerificationTokenRepository.class);

        new VerificationTokenCleanup(tokens, Clock.fixed(now, ZoneOffset.UTC)).deleteExpiredTokens();

        verify(tokens).deleteExpiredBefore(now.minus(Duration.ofDays(1)));
    }
}
