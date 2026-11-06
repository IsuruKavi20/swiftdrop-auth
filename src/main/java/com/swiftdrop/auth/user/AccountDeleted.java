package com.swiftdrop.auth.user;

import java.util.UUID;

/**
 * The owner deleted their account (outbox event, published by the account module). Each module removes what it
 * holds for that person (e.g. the google module unlinks Google logins); identity step 6 sends it to SwiftDrop as the
 * RISC "account-purged" signal. It lives here, with the user, so any module can react without depending on account.
 */
public record AccountDeleted(UUID userId) {
}
