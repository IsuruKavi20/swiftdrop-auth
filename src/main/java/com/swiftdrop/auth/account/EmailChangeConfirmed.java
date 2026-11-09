package com.swiftdrop.auth.account;

import java.util.UUID;

/** The login email changed (outbox): the old address gets its undo link. Identity step 6 will also publish it.
 * frontendId: the app the request came from (null = the primary one); emailed links go there. */
record EmailChangeConfirmed(UUID requestId, String frontendId) {
}
