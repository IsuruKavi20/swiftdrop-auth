package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.user.RoleName;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/** The roles one can apply for: COURIER and DISPATCHER only (ADMIN never; MERCHANT has its own flow). */
public enum ApplicableRole {
    COURIER("role:approve-courier"),
    DISPATCHER("role:approve-dispatcher");

    private final String approvePermission;

    ApplicableRole(String approvePermission) {
        this.approvePermission = approvePermission;
    }

    public RoleName roleName() {
        return RoleName.valueOf(name());
    }

    /** The roles a caller may decide, from the permissions in their token (least privilege). */
    public static Set<RoleName> decidableWith(Collection<String> permissions) {
        return Arrays.stream(values()).filter(role -> permissions.contains(role.approvePermission))
                .map(ApplicableRole::roleName).collect(Collectors.toUnmodifiableSet());
    }
}
