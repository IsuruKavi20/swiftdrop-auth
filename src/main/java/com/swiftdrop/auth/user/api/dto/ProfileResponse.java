package com.swiftdrop.auth.user.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.swiftdrop.auth.user.ProfileView;

/**
 * The identity profile with OpenID Connect standard claim names (the same names /userinfo will use).
 * Absent values are left out. {@code updated_at} is seconds since 1970 (OIDC Core 5.1).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ProfileResponse(
        String sub,
        String name,
        @JsonProperty("given_name") String givenName,
        @JsonProperty("family_name") String familyName,
        String picture,
        String locale,
        String email,
        @JsonProperty("email_verified") boolean emailVerified,
        @JsonProperty("updated_at") Long updatedAt) {

    public static ProfileResponse from(ProfileView view) {
        return new ProfileResponse(view.id().toString(), view.name(), view.givenName(), view.familyName(),
                view.pictureUrl(), view.locale(), view.email(), view.emailVerified(),
                view.updatedAt() == null ? null : view.updatedAt().getEpochSecond());
    }

    /** Personal data: never print it. */
    @Override
    public String toString() {
        return "ProfileResponse[redacted]";
    }
}
