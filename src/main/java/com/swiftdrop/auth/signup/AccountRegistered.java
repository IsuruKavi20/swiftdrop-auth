package com.swiftdrop.auth.signup;

import java.util.UUID;

/** A new account was saved. Carries only the ID: events are stored in the outbox, so no PII. */
public record AccountRegistered(UUID userId) {
}
