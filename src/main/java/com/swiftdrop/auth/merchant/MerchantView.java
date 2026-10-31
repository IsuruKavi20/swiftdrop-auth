package com.swiftdrop.auth.merchant;

import java.time.Instant;
import java.util.UUID;

/** What the API may show of a merchant application. */
public record MerchantView(UUID id, UUID userId, String businessName, String registrationNumber, String website,
                           MerchantStatus status, RejectionReason decisionReason, Instant createdAt,
                           Instant decidedAt) {

    static MerchantView of(Merchant merchant) {
        return new MerchantView(merchant.getId(), merchant.getUserId(), merchant.getBusinessName(),
                merchant.getRegistrationNumber(), merchant.getWebsite(), merchant.getStatus(),
                merchant.getDecisionReason(), merchant.getCreatedAt(), merchant.getDecidedAt());
    }
}
