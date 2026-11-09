package com.swiftdrop.auth.admin.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Why an administrator blocks, unblocks or deletes someone. Stored in the audit log: no email addresses. */
public record ReasonBody(@NotBlank @Size(min = 3, max = 200) String reason) {
}
