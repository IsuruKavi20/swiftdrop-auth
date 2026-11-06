package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.user.RoleName;

/** The roles one can apply for: COURIER and DISPATCHER only (ADMIN never; MERCHANT has its own flow). */
public enum ApplicableRole {
    COURIER, DISPATCHER;

    public RoleName roleName() {
        return RoleName.valueOf(name());
    }
}
