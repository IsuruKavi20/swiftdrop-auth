package com.swiftdrop.auth.session;

import com.swiftdrop.auth.common.privacy.ExportMap;
import com.swiftdrop.auth.common.privacy.PersonalDataExporter;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.UUID;

/** The open sessions (logged-in devices): when last refreshed and until when. Never the token or its hash. */
@Component
class SessionDataExporter implements PersonalDataExporter {

    private final RefreshTokenRepository tokens;
    private final Clock clock;

    SessionDataExporter(RefreshTokenRepository tokens, Clock clock) {
        this.tokens = tokens;
        this.clock = clock;
    }

    @Override
    public String section() {
        return "sessions";
    }

    @Override
    @Transactional(readOnly = true)
    public Object export(UUID userId) {
        return tokens.findOpenSessions(userId, clock.instant()).stream().map(token -> ExportMap.of()
                .put("last_refreshed_at", token.getCreatedAt())
                .put("idle_expires_at", token.getExpiresAt())
                .put("ends_at", token.getFamilyExpiresAt())
                .build()).toList();
    }
}
