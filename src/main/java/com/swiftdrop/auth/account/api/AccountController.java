package com.swiftdrop.auth.account.api;

import com.swiftdrop.auth.account.AccountDeletionService;
import com.swiftdrop.auth.account.EmailChangeService;
import com.swiftdrop.auth.account.api.dto.CurrentPasswordBody;
import com.swiftdrop.auth.account.PasswordChangeService;
import com.swiftdrop.auth.account.PersonalDataExport;
import com.swiftdrop.auth.account.api.dto.PasswordChangeBody;
import com.swiftdrop.auth.token.TokenResponse;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import com.swiftdrop.auth.account.api.dto.EmailChangeBody;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** HTTP only: sensitive changes to the logged-in user's own account (identity step 3). */
@RestController
public class AccountController {

    private static final String EXPORT_FILE = "attachment; filename=\"swiftdrop-auth-my-data.json\"";

    private final EmailChangeService emailChanges;
    private final PasswordChangeService passwordChanges;
    private final PersonalDataExport export;
    private final AccountDeletionService deletion;

    AccountController(EmailChangeService emailChanges, PasswordChangeService passwordChanges,
                      PersonalDataExport export, AccountDeletionService deletion) {
        this.emailChanges = emailChanges;
        this.passwordChanges = passwordChanges;
        this.export = export;
        this.deletion = deletion;
    }

    /**
     * Deletes my account: 202 because the erasure continues in the background (other modules, later SwiftDrop).
     * The current password is required; afterwards nothing can log in to this account again.
     */
    @DeleteMapping(value = ApiPaths.V1 + "/me", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> deleteMyAccount(@AuthenticationPrincipal Jwt token,
                                                @Valid @RequestBody CurrentPasswordBody body) {
        deletion.delete(CurrentUser.idOf(token), body.currentPassword());
        return ResponseEntity.accepted().build();
    }

    /** Everything the auth service holds about me, as a JSON download (never cached: personal data). */
    @GetMapping(value = ApiPaths.V1 + "/me/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> exportMyData(@AuthenticationPrincipal Jwt token) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, EXPORT_FILE)
                .body(export.of(CurrentUser.idOf(token)));
    }

    /**
     * Ends every session (other devices are logged out) and returns fresh tokens for this device, shaped like a
     * login response. Never cached (RFC 6749 5.1).
     */
    @PostMapping(value = ApiPaths.V1 + "/me/password", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> changePassword(@AuthenticationPrincipal Jwt token,
                                                        @Valid @RequestBody PasswordChangeBody body) {
        TokenResponse tokens = passwordChanges.change(CurrentUser.idOf(token), body.currentPassword(),
                body.newPassword()).toResponse();
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache")
                .body(tokens);
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
