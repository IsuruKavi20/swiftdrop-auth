package com.swiftdrop.auth.merchant.api.dto;

import com.swiftdrop.auth.merchant.MerchantApplications;
import com.swiftdrop.auth.merchant.RejectionReason;
import jakarta.validation.constraints.NotNull;

/** {@code reason} is required for REJECT and must be absent for APPROVE (checked by the service). */
public record MerchantDecisionRequest(@NotNull MerchantApplications.Decision decision, RejectionReason reason) {
}
