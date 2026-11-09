package com.swiftdrop.auth.admin.api;

import com.swiftdrop.auth.admin.AdminUsers;
import com.swiftdrop.auth.audit.Actor;
import com.swiftdrop.auth.admin.RoleAdministration;
import com.swiftdrop.auth.admin.api.dto.ReasonBody;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import com.swiftdrop.auth.admin.api.dto.AdminUserResponse;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.RequirePermission;
import com.swiftdrop.auth.user.RoleName;
import org.springframework.security.authentication.BadCredentialsException;
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
    private final AdminUsers adminUsers;

    public AdminUserController(RoleAdministration administration, AdminUsers adminUsers) {
        this.administration = administration;
        this.adminUsers = adminUsers;
    }

    /** Identity step 9b: one person, by id (search stays exact-email only: no browsing everyone). */
    @GetMapping("/{userId}")
    @RequirePermission("user:read")
    public AdminUsers.UserDetail detail(@PathVariable UUID userId) {
        return adminUsers.detail(userId);
    }

    @PostMapping("/{userId}/block")
    @RequirePermission("user:manage-status")
    public AdminUsers.UserDetail block(@AuthenticationPrincipal Jwt caller, @PathVariable UUID userId,
                                       @Valid @RequestBody ReasonBody body) {
        return adminUsers.block(Actor.user(callerId(caller)), userId, body.reason());
    }

    @PostMapping("/{userId}/unblock")
    @RequirePermission("user:manage-status")
    public AdminUsers.UserDetail unblock(@AuthenticationPrincipal Jwt caller, @PathVariable UUID userId,
                                         @Valid @RequestBody ReasonBody body) {
        return adminUsers.unblock(Actor.user(callerId(caller)), userId, body.reason());
    }

    @PostMapping("/{userId}/sessions/end")
    @RequirePermission("user:manage-status")
    public AdminUsers.UserDetail endSessions(@AuthenticationPrincipal Jwt caller, @PathVariable UUID userId,
                                             @Valid @RequestBody ReasonBody body) {
        return adminUsers.endSessions(Actor.user(callerId(caller)), userId, body.reason());
    }

    /** The step 8 erasure: tombstone now, hard delete once every receiver confirmed (30 days at most). */
    @DeleteMapping("/{userId}")
    @RequirePermission("user:delete")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt caller, @PathVariable UUID userId,
                                       @Valid @RequestBody ReasonBody body) {
        adminUsers.delete(Actor.user(callerId(caller)), userId, body.reason());
        return ResponseEntity.noContent().build();
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
        try {
            return UUID.fromString(caller.getSubject());
        } catch (IllegalArgumentException notAUser) {
            // a merchant machine token (sub = mc_...) is not a person: 401, never a 500
            throw new BadCredentialsException("Not a user token");
        }
    }
}
