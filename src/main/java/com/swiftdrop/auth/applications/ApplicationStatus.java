package com.swiftdrop.auth.applications;

/** Where a role application stands. Only PENDING is open; the others are final. */
public enum ApplicationStatus {
    PENDING,
    APPROVED,
    REJECTED,
    WITHDRAWN
}
