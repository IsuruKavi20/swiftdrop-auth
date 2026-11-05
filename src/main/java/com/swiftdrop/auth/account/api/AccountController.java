package com.swiftdrop.auth.account.api;

import com.swiftdrop.auth.account.EmailChangeService;
import com.swiftdrop.auth.account.api.dto.EmailChangeBody;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** HTTP only: sensitive changes to the logged-in user's own account (identity step 3). */
@RestController
public class AccountController {

    private final EmailChangeService emailChanges;

    AccountController(EmailChangeService emailChanges) {
        this.emailChanges = emailChanges;
    }

    /**
     * Always 202 when the password is right: whether the new address already has an account is never revealed.
     * The change happens only when the new address confirms the emailed link.
     */
    @PostMapping(value = ApiPaths.V1 + "/me/email-change", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> requestEmailChange(@AuthenticationPrincipal Jwt token,
                                                   @Valid @RequestBody EmailChangeBody body) {
        emailChanges.request(CurrentUser.idOf(token), body.newEmail(), body.currentPassword());
        return ResponseEntity.accepted().build();
    }
}
