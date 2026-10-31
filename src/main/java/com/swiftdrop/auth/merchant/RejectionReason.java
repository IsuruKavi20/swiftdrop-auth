package com.swiftdrop.auth.merchant;

/** A fixed list instead of free text: no personal data in the database, nothing to inject into an admin screen. */
public enum RejectionReason {
    INCOMPLETE_INFORMATION,
    UNVERIFIABLE_BUSINESS,
    NOT_ELIGIBLE,
    OTHER
}
