package com.swiftdrop.auth.user.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.user.IfMatchRequiredException;
import com.swiftdrop.auth.user.InvalidProfileException;
import com.swiftdrop.auth.user.ProfilePatch;
import com.swiftdrop.auth.user.ProfileService;
import com.swiftdrop.auth.user.ProfileView;
import com.swiftdrop.auth.user.api.dto.ProfileResponse;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** HTTP only: the logged-in user's own identity profile (identity step 3a). Rules live in ProfileService. */
@RestController
public class ProfileController {

    static final String PATH = ApiPaths.V1 + "/me/profile";
    private static final String MERGE_PATCH = "application/merge-patch+json";

    private final ProfileService profiles;

    ProfileController(ProfileService profiles) {
        this.profiles = profiles;
    }

    @GetMapping(value = PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ProfileResponse> read(@AuthenticationPrincipal Jwt token) {
        return respond(profiles.get(userIdOf(token)));
    }

    /** JSON Merge Patch (RFC 7396) with a required If-Match (RFC 7232): 428 without it, 412 if it is stale. */
    @PatchMapping(value = PATH, consumes = {MERGE_PATCH, MediaType.APPLICATION_JSON_VALUE},
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ProfileResponse> edit(@AuthenticationPrincipal Jwt token,
                                                @RequestHeader(value = HttpHeaders.IF_MATCH, required = false)
                                                String ifMatch,
                                                @RequestBody JsonNode body) {
        UUID userId = userIdOf(token);
        if (ifMatch == null || ifMatch.isBlank()) {
            throw new IfMatchRequiredException();
        }
        return respond(profiles.update(userId, ifMatch.strip(), patchOf(body)));
    }

    // Only a JSON object of text-or-null values: numbers, arrays, objects are refused, field names are checked
    private static ProfilePatch patchOf(JsonNode body) {
        if (body == null || !body.isObject()) {
            throw new InvalidProfileException("body", "JsonObject");
        }
        Map<String, String> changes = new HashMap<>();
        for (Map.Entry<String, JsonNode> field : body.properties()) {
            JsonNode value = field.getValue();
            if (!value.isNull() && !value.isString()) {
                throw new InvalidProfileException(ProfilePatch.FIELDS.contains(field.getKey()) ? field.getKey()
                        : "body", "Text");
            }
            changes.put(field.getKey(), value.isNull() ? null : value.stringValue());
        }
        return ProfilePatch.of(changes);
    }

    private static ResponseEntity<ProfileResponse> respond(ProfileView view) {
        // Personal data: never kept by browsers or shared caches
        return ResponseEntity.ok().eTag(view.etag()).cacheControl(CacheControl.noStore())
                .body(ProfileResponse.from(view));
    }

    // A user token's sub is the user's UUID; a merchant machine token's sub is its client id: no profile there
    private static UUID userIdOf(Jwt token) {
        try {
            return UUID.fromString(token.getSubject());
        } catch (IllegalArgumentException notAUser) {
            throw new AccessDeniedException("Only user tokens have a profile");
        }
    }
}
