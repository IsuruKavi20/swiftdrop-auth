package com.swiftdrop.auth.user;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;

/** The permissions a set of roles grants: what goes into a token's "entitlements" claim. */
@Service
public class RolePermissions {

    private final RoleRepository roles;

    public RolePermissions(RoleRepository roles) {
        this.roles = roles;
    }

    @Transactional(readOnly = true)
    public List<String> permissionsOf(Collection<RoleName> roleNames) {
        return roles.findByNameIn(roleNames).stream()
                .flatMap(role -> role.permissionNames().stream())
                .distinct()
                .sorted()
                .toList();
    }
}
