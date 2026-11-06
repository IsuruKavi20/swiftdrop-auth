package com.swiftdrop.auth.applications.api.dto;

import com.swiftdrop.auth.applications.Decision;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Body of POST /admin/role-applications/{id}/decision. The reason is shown to the applicant. */
public record DecisionBody(@NotNull Decision decision, @Size(max = 500) String reason) {

    /** Free text about a person: never in logs. */
    @Override
    public String toString() {
        return "DecisionBody[decision=" + decision + ", reason=redacted]";
    }
}
