package com.swiftdrop.auth.signup;

import java.util.UUID;

/** Someone signed up with an address that already has an account. The owner is told by email.
 * frontendId: the app the request came from (null = the primary one); emailed links go there. */
public record SignupAttemptOnExistingAccount(UUID userId, String frontendId) {
}
