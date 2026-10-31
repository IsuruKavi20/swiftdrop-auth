package com.swiftdrop.auth.merchant.api.dto;

import com.swiftdrop.auth.merchant.MerchantStatus;
import com.swiftdrop.auth.merchant.MerchantView;
import com.swiftdrop.auth.merchant.RejectionReason;

import java.time.Instant;
import java.util.UUID;

public record MerchantApplicationResponse(UUID id, UUID userId, String businessName, String registrationNumber,
                                          String website, MerchantStatus status, RejectionReason decisionReason,
                                          Instant createdAt, Instant decidedAt) {

    public static MerchantApplicationResponse from(MerchantView merchant) {
        return new MerchantApplicationResponse(merchant.id(), merchant.userId(), merchant.businessName(),
                merchant.registrationNumber(), merchant.website(), merchant.status(), merchant.decisionReason(),
                merchant.createdAt(), merchant.decidedAt());
    }
}
