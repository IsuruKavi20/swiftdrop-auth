package com.swiftdrop.auth.merchant.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.merchant.MerchantApplications;
import com.swiftdrop.auth.merchant.MerchantClients;
import com.swiftdrop.auth.merchant.api.dto.CreateClientRequest;
import com.swiftdrop.auth.merchant.api.dto.CreatedClientResponse;
import com.swiftdrop.auth.merchant.api.dto.MerchantApplicationRequest;
import com.swiftdrop.auth.merchant.api.dto.MerchantApplicationResponse;
import com.swiftdrop.auth.merchant.api.dto.MerchantClientResponse;
import com.swiftdrop.auth.security.RequirePermission;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * For people (user tokens): apply to become a merchant, and manage the merchant's API credentials. A merchant
 * MACHINE token (sub = mc_...) has no user id, so it can't create more credentials: 401.
 */
@RestController
@RequestMapping(ApiPaths.V1 + "/merchants")
public class MerchantController {

    private final MerchantApplications applications;
    private final MerchantClients clients;

    public MerchantController(MerchantApplications applications, MerchantClients clients) {
        this.applications = applications;
        this.clients = clients;
    }

    @PostMapping("/application")
    public ResponseEntity<MerchantApplicationResponse> apply(@AuthenticationPrincipal Jwt caller,
                                                             @Valid @RequestBody MerchantApplicationRequest request) {
        var application = new MerchantApplications.Application(request.businessName(), request.registrationNumber(),
                request.website());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(MerchantApplicationResponse.from(applications.apply(userId(caller), application)));
    }

    @GetMapping("/application")
    public MerchantApplicationResponse ownApplication(@AuthenticationPrincipal Jwt caller) {
        return MerchantApplicationResponse.from(applications.findOwn(userId(caller)));
    }

    @PostMapping("/me/clients")
    @RequirePermission("merchant:api-access")
    public ResponseEntity<CreatedClientResponse> createClient(@AuthenticationPrincipal Jwt caller,
                                                              @Valid @RequestBody CreateClientRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(CreatedClientResponse.from(clients.create(userId(caller), request.name())));
    }

    @GetMapping("/me/clients")
    @RequirePermission("merchant:api-access")
    public List<MerchantClientResponse> listClients(@AuthenticationPrincipal Jwt caller) {
        return clients.list(userId(caller)).stream().map(MerchantClientResponse::from).toList();
    }

    @DeleteMapping("/me/clients/{clientId}")
    @RequirePermission("merchant:api-access")
    public ResponseEntity<Void> revokeClient(@AuthenticationPrincipal Jwt caller, @PathVariable String clientId) {
        clients.revoke(userId(caller), clientId);
        return ResponseEntity.noContent().build();
    }

    static UUID userId(Jwt caller) {
        try {
            return UUID.fromString(caller.getSubject());
        } catch (IllegalArgumentException notAUser) {
            // e.g. a merchant client token: these endpoints are for people only
            throw new BadCredentialsException("Not a user token");
        }
    }
}
