package com.swiftdrop.auth.signup;

import java.util.UUID;

/** A new account was saved. Carries only the ID: events are stored in the outbox, so no PII.
 * frontendId: the app the request came from (null = the primary one); emailed links go there. */
public record AccountRegistered(UUID userId, String frontendId) {
}
