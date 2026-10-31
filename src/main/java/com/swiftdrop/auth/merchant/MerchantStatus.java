package com.swiftdrop.auth.merchant;

public enum MerchantStatus {
    PENDING,
    APPROVED,
    REJECTED,
    /** Set by an admin later (e.g. fraud): its clients get no new tokens. */
    SUSPENDED
}
