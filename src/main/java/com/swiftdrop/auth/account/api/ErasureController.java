package com.swiftdrop.auth.account.api;

import com.swiftdrop.auth.account.ErasureConfirmations;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.directory.DirectoryProperties;
import com.swiftdrop.auth.directory.ServiceClients;
import com.swiftdrop.auth.security.RequirePermission;
import com.swiftdrop.auth.signals.EventsProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * HTTP only (identity step 8): a receiver confirms it erased a deleted person. Only a receiver's own service client:
 * "svc_swiftdrop-backend" confirms for receiver "swiftdrop-backend", with permission erasure:confirm.
 */
@RestController
public class ErasureController {

    private final ErasureConfirmations confirmations;
    private final EventsProperties events;

    ErasureController(ErasureConfirmations confirmations, EventsProperties events) {
        this.confirmations = confirmations;
        this.events = events;
    }

    @PostMapping(ApiPaths.V1 + "/directory/erasure/{userId}/confirm")
    @RequirePermission(DirectoryProperties.ERASURE_CONFIRM)
    public ResponseEntity<Void> confirm(@AuthenticationPrincipal Jwt token, @PathVariable UUID userId) {
        confirmations.confirm(receiverOf(token), userId);
        return ResponseEntity.noContent().build();
    }

    // The client "svc_<receiver id>" confirms only for the configured receiver "<receiver id>"
    private String receiverOf(Jwt token) {
        String clientId = token.getClaimAsString("client_id");
        if (!ServiceClients.isServiceClientId(clientId)) {
            throw new AccessDeniedException("Only service clients confirm erasures");
        }
        String receiverId = clientId.substring(ServiceClients.PREFIX.length());
        return events.receivers().stream().map(EventsProperties.Receiver::id).filter(receiverId::equals).findFirst()
                .orElseThrow(() -> new AccessDeniedException("No events receiver for this client"));
    }
}
