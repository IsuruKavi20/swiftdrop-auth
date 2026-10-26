package com.swiftdrop.auth.signup;

import java.util.UUID;

/** Someone signed up with an address that already has an account. The owner is told by email. */
public record SignupAttemptOnExistingAccount(UUID userId) {
}
