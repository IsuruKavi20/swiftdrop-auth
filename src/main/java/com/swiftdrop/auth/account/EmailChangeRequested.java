package com.swiftdrop.auth.account;

import java.util.UUID;

/** Stored in the outbox with the request: its emails are sent after the commit, and retried if sending fails. */
record EmailChangeRequested(UUID requestId) {
}
