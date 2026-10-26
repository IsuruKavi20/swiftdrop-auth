package com.swiftdrop.auth.verification;

import java.util.UUID;

/** "Send a fresh verification email to this user." Carries only the ID: events are stored, so no PII. */
public record VerificationEmailRequested(UUID userId) {
}
