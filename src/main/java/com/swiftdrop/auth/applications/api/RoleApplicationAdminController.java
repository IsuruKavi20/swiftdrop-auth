package com.swiftdrop.auth.applications.api;

import com.swiftdrop.auth.applications.ApplicableRole;
import com.swiftdrop.auth.applications.ApplicationForApprover;
import com.swiftdrop.auth.applications.ApplicationStatus;
import com.swiftdrop.auth.applications.RoleApplicationException;
import com.swiftdrop.auth.applications.RoleApplicationView;
import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.applications.RoleApplications;
import com.swiftdrop.auth.applications.api.dto.DecisionBody;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * HTTP only: the approvers' side of role applications (identity step 7b). Who may decide which role comes from the
 * caller's token permissions (role:approve-courier, role:approve-dispatcher); every rule is in RoleApplications.
 * The screens live in SwiftDrop's frontend (admin/dispatcher section) and call this with the person's own token.
 */
@RestController
@RequestMapping(ApiPaths.V1 + "/admin/role-applications")
public class RoleApplicationAdminController {

    private static final int MAX_COUNT = 100;

    private final RoleApplications applications;

    RoleApplicationAdminController(RoleApplications applications) {
        this.applications = applications;
    }

    /** ?status=PENDING (default) &role=COURIER|DISPATCHER (optional) &count=50 (max 100): oldest first. */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ApplicationForApprover> queue(Authentication caller,
                                              @RequestParam(required = false) ApplicableRole role,
                                              @RequestParam(defaultValue = "PENDING") ApplicationStatus status,
                                              @RequestParam(defaultValue = "50") int count) {
        if (count < 1 || count > MAX_COUNT) {
            throw new RoleApplicationException(ErrorCode.VALIDATION_FAILED);
        }
        return applications.queue(ApplicableRole.decidableWith(permissionsOf(caller)),
                role == null ? null : role.roleName(), status, count);
    }

    @PostMapping(value = "/{id}/decision", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public RoleApplicationView decide(@AuthenticationPrincipal Jwt token, Authentication caller, @PathVariable UUID id,
                                      @Valid @RequestBody DecisionBody body) {
        return applications.decide(CurrentUser.idOf(token), ApplicableRole.decidableWith(permissionsOf(caller)), id,
                body.decision(), body.reason());
    }

    private static List<String> permissionsOf(Authentication caller) {
        return caller.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    }
}
