package com.swiftdrop.auth.applications;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.swiftdrop.auth.user.RoleName;

import java.time.Instant;
import java.util.UUID;

/** A role application as the applicant (and later the approver) sees it. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RoleApplicationView(
        UUID id,
        RoleName role,
        ApplicationStatus status,
        String note,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("decided_at") Instant decidedAt,
        @JsonProperty("decision_reason") String decisionReason) {

    static RoleApplicationView of(RoleApplication application) {
        return new RoleApplicationView(application.getId(), application.getRole(), application.getStatus(),
                application.getNote(), application.getCreatedAt(), application.getDecidedAt(),
                application.getDecisionReason());
    }
}
