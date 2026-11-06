package com.swiftdrop.auth.account;

import java.util.UUID;

/** The login email changed (outbox): the old address gets its undo link. Identity step 6 will also publish it. */
record EmailChangeConfirmed(UUID requestId) {
}
