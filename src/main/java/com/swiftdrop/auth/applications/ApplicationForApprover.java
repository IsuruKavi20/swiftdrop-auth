package com.swiftdrop.auth.applications;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.swiftdrop.auth.user.RoleName;

import java.time.Instant;
import java.util.UUID;

/** A role application as an approver sees it: with who applied (id and name only, the minimum to decide). */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApplicationForApprover(
        UUID id,
        RoleName role,
        ApplicationStatus status,
        String note,
        Applicant applicant,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("decided_at") Instant decidedAt,
        @JsonProperty("decision_reason") String decisionReason) {

    public record Applicant(UUID id, String name) {
    }

    static ApplicationForApprover of(RoleApplication application, String applicantName) {
        return new ApplicationForApprover(application.getId(), application.getRole(), application.getStatus(),
                application.getNote(), new Applicant(application.getUserId(), applicantName),
                application.getCreatedAt(), application.getDecidedAt(), application.getDecisionReason());
    }
}
