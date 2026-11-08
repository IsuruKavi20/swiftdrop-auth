package com.swiftdrop.auth.applications.api.dto;

import com.swiftdrop.auth.applications.ApplicableRole;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Body of POST /me/role-applications. Only the roles one can apply for exist in this type. */
public record ApplyBody(@NotNull ApplicableRole role, @Size(max = 500) String note) {

    /** The note is the applicant's own words: never in logs. */
    @Override
    public String toString() {
        return "ApplyBody[role=" + role + ", note=redacted]";
    }
}
