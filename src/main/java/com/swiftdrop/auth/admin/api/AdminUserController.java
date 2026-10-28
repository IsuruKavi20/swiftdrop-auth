package com.swiftdrop.auth.admin.api;

import com.swiftdrop.auth.admin.RoleAdministration;
import com.swiftdrop.auth.admin.api.dto.AdminUserResponse;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.RequirePermission;
import com.swiftdrop.auth.user.RoleName;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Role administration. PUT/DELETE on /users/{id}/roles/{role} are idempotent: the role is a
 * member of the user's role set, added or removed.
 */
@RestController
@RequestMapping(ApiPaths.V1 + "/admin/users")
public class AdminUserController {

    private final RoleAdministration administration;

    public AdminUserController(RoleAdministration administration) {
        this.administration = administration;
    }

    @GetMapping
    @RequirePermission("user:read")
    public AdminUserResponse findByEmail(@RequestParam String email) {
        return AdminUserResponse.from(administration.findByEmail(email));
    }

    @PutMapping("/{userId}/roles/{role}")
    @RequirePermission("user:manage-roles")
    public AdminUserResponse grant(@AuthenticationPrincipal Jwt caller, @PathVariable UUID userId,
                                   @PathVariable RoleName role) {
        return AdminUserResponse.from(administration.grant(callerId(caller), userId, role));
    }

    @DeleteMapping("/{userId}/roles/{role}")
    @RequirePermission("user:manage-roles")
    public AdminUserResponse revoke(@AuthenticationPrincipal Jwt caller, @PathVariable UUID userId,
                                    @PathVariable RoleName role) {
        return AdminUserResponse.from(administration.revoke(callerId(caller), userId, role));
    }

    private static UUID callerId(Jwt caller) {
        return UUID.fromString(caller.getSubject());
    }
}
