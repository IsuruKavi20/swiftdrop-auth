package com.swiftdrop.auth.account.api;

import com.swiftdrop.auth.account.EmailChangeService;
import com.swiftdrop.auth.account.api.dto.LinkTokenBody;
import com.swiftdrop.auth.common.web.ApiPaths;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP only: the emailed email-change links (no login needed: the one-time token is the credential). The frontend
 * page reads the token from the link's #fragment and POSTs it when the user presses "Confirm".
 */
@RestController
public class EmailChangeLinkController {

    private final EmailChangeService emailChanges;

    EmailChangeLinkController(EmailChangeService emailChanges) {
        this.emailChanges = emailChanges;
    }

    @PostMapping(value = ApiPaths.AUTH + "/email-change/confirm", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void confirm(@Valid @RequestBody LinkTokenBody body) {
        emailChanges.confirm(body.token());
    }
}
