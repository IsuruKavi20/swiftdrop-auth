package com.swiftdrop.auth.signup;

import java.util.UUID;

/** What the signup use case returns. Entities never leave the service layer. */
public record SignupResult(UUID userId) {
}
