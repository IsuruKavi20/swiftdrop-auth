package com.swiftdrop.auth.account;

import java.util.UUID;

/** Stored in the outbox with the request: its emails are sent after the commit, and retried if sending fails.
 * frontendId: the app the request came from (null = the primary one); emailed links go there. */
record EmailChangeRequested(UUID requestId, String frontendId) {
}
