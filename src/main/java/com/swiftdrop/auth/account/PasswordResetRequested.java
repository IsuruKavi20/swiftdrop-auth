package com.swiftdrop.auth.account;

import java.util.UUID;

/** Outbox event (identity step 11a): someone asked for a reset link for this account; the listener sends it. */
record PasswordResetRequested(UUID userId, String frontendId) {
}
