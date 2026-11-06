package com.swiftdrop.auth.account;

import java.util.UUID;

/** Outbox event: the password changed, so the owner gets a notice email. Identity step 6 will publish it too. */
record PasswordChanged(UUID userId) {
}
