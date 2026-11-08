package com.swiftdrop.auth.signals.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.directory.DirectoryProperties;
import com.swiftdrop.auth.directory.ServiceClients;
import com.swiftdrop.auth.security.RequirePermission;
import com.swiftdrop.auth.signals.EventPolling;
import com.swiftdrop.auth.signals.EventsProperties;
import com.swiftdrop.auth.signals.api.dto.PollRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * HTTP only: RFC 8936 poll endpoint (identity step 6d). Only a receiver's own service client may poll: receiver
 * "swiftdrop-backend" polls as client "svc_swiftdrop-backend" with permission events:read.
 */
@RestController
public class EventPollController {

    private static final int DEFAULT_MAX_EVENTS = 50;

    private final EventPolling polling;

    EventPollController(EventPolling polling) {
        this.polling = polling;
    }

    @PostMapping(value = ApiPaths.V1 + "/events/poll", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @RequirePermission(DirectoryProperties.EVENTS_READ)
    public ResponseEntity<Map<String, Object>> poll(@AuthenticationPrincipal Jwt token,
                                                    @Valid @RequestBody PollRequest request) {
        EventsProperties.Receiver receiver = receiverOf(token);
        Map<UUID, String> errors = new LinkedHashMap<>();
        if (request.setErrs() != null) {
            request.setErrs().forEach((jti, error) -> errors.put(eventId(jti),
                    error == null || error.err() == null ? "unspecified" : error.err()));
        }
        EventPolling.PollResult result = polling.poll(receiver, request.ack() == null ? List.of() : request.ack(),
                errors, request.maxEvents() == null ? DEFAULT_MAX_EVENTS : request.maxEvents());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sets", result.sets());
        body.put("moreAvailable", result.moreAvailable());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
    }

    // A malformed id is the caller's mistake: 400, never a 500
    private static UUID eventId(String jti) {
        try {
            return UUID.fromString(jti);
        } catch (IllegalArgumentException notAnId) {
            throw new InvalidPollRequestException();
        }
    }

    // The client "svc_<receiver id>" may only ever see the receiver "<receiver id>"
    private EventsProperties.Receiver receiverOf(Jwt token) {
        String clientId = token.getClaimAsString("client_id");
        if (!ServiceClients.isServiceClientId(clientId)) {
            throw new AccessDeniedException("Only service clients poll events");
        }
        return polling.receiver(clientId.substring(ServiceClients.PREFIX.length()))
                .orElseThrow(() -> new AccessDeniedException("No events receiver for this client"));
    }
}
