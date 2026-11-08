package com.swiftdrop.auth.applications.api;

import com.swiftdrop.auth.applications.RoleApplicationView;
import com.swiftdrop.auth.applications.RoleApplications;
import com.swiftdrop.auth.applications.api.dto.ApplyBody;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** HTTP only: the logged-in person's own role applications (identity step 7a). */
@RestController
@RequestMapping(ApiPaths.V1 + "/me/role-applications")
public class RoleApplicationController {

    private final RoleApplications applications;

    RoleApplicationController(RoleApplications applications) {
        this.applications = applications;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public RoleApplicationView apply(@AuthenticationPrincipal Jwt token, @Valid @RequestBody ApplyBody body) {
        return applications.apply(CurrentUser.idOf(token), body.role().roleName(), body.note());
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public List<RoleApplicationView> mine(@AuthenticationPrincipal Jwt token) {
        return applications.mine(CurrentUser.idOf(token));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void withdraw(@AuthenticationPrincipal Jwt token, @PathVariable UUID id) {
        applications.withdraw(CurrentUser.idOf(token), id);
    }
}
