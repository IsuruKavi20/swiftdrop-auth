package com.swiftdrop.auth.directory.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.directory.DirectoryProperties;
import com.swiftdrop.auth.directory.DirectoryService;
import com.swiftdrop.auth.directory.ServiceClients;
import com.swiftdrop.auth.directory.api.dto.LookupBody;
import com.swiftdrop.auth.security.RequirePermission;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

/**
 * HTTP only: the Directory API for SwiftDrop's backend (identity step 5). Every endpoint needs directory:read, which
 * only service clients (svc_...) have; no user role grants it, not even ADMIN. Never cached (personal data).
 */
@RestController
@RequestMapping(value = ApiPaths.V1 + "/directory/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class DirectoryController {

    private final DirectoryService directory;

    DirectoryController(DirectoryService directory) {
        this.directory = directory;
    }

    @GetMapping("/{id}")
    @RequirePermission(DirectoryProperties.READ)
    public ResponseEntity<Map<String, Object>> get(@PathVariable UUID id, @AuthenticationPrincipal Jwt token,
                                                   Authentication caller) {
        return noStore(directory.get(id, mayReadEmail(caller), serviceClient(token).getSubject()));
    }

    @PostMapping(value = "/lookup", consumes = MediaType.APPLICATION_JSON_VALUE)
    @RequirePermission(DirectoryProperties.READ)
    public ResponseEntity<Map<String, Object>> lookup(@Valid @RequestBody LookupBody body,
                                                      @AuthenticationPrincipal Jwt token, Authentication caller) {
        return noStore(directory.lookup(body.ids(), mayReadEmail(caller), serviceClient(token).getSubject()));
    }

    /** SCIM-style: ?role=COURIER&status=ACTIVE&startIndex=1&count=50 (status defaults to ACTIVE, count max 100). */
    @GetMapping
    @RequirePermission(DirectoryProperties.READ)
    public ResponseEntity<Map<String, Object>> list(@RequestParam(required = false) String role,
                                                    @RequestParam(required = false) String status,
                                                    @RequestParam(required = false) Integer startIndex,
                                                    @RequestParam(required = false) Integer count,
                                                    @AuthenticationPrincipal Jwt token, Authentication caller) {
        return noStore(directory.list(role, status, startIndex, count, mayReadEmail(caller),
                serviceClient(token).getSubject()));
    }

    // Defence in depth: besides the permission, the caller must be one of our service clients (svc_...). Even a token
    // from a user app that somehow carried directory:read (a seed-data mistake) is refused.
    private static Jwt serviceClient(Jwt token) {
        if (!ServiceClients.isServiceClientId(token.getClaimAsString("client_id"))) {
            throw new AccessDeniedException("The directory is for service clients only");
        }
        return token;
    }

    private static boolean mayReadEmail(Authentication caller) {
        return caller.getAuthorities().stream()
                .anyMatch(authority -> DirectoryProperties.READ_EMAIL.equals(authority.getAuthority()));
    }

    private static ResponseEntity<Map<String, Object>> noStore(Map<String, Object> body) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
    }
}
