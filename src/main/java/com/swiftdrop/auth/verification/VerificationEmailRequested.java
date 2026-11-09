package com.swiftdrop.auth.verification;

import java.util.UUID;

/** "Send a fresh verification email to this user." Carries only the ID: events are stored, so no PII.
 * frontendId: the app the request came from (null = the primary one); emailed links go there. */
public record VerificationEmailRequested(UUID userId, String frontendId) {
}
