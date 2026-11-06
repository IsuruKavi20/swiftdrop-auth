package com.swiftdrop.auth.merchant;

import com.swiftdrop.auth.common.privacy.ExportMap;
import com.swiftdrop.auth.common.privacy.PersonalDataExporter;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/** The merchant application, if any. API client secrets (their hashes) are never exported. */
@Component
class MerchantDataExporter implements PersonalDataExporter {

    private final MerchantRepository merchants;

    MerchantDataExporter(MerchantRepository merchants) {
        this.merchants = merchants;
    }

    @Override
    public String section() {
        return "merchant";
    }

    @Override
    @Transactional(readOnly = true)
    public Object export(UUID userId) {
        return merchants.findByUserId(userId).map(merchant -> ExportMap.of()
                .put("business_name", merchant.getBusinessName())
                .put("registration_number", merchant.getRegistrationNumber())
                .put("website", merchant.getWebsite())
                .put("status", merchant.getStatus())
                .put("decision_reason", merchant.getDecisionReason())
                .put("decided_at", merchant.getDecidedAt())
                .put("applied_at", merchant.getCreatedAt())
                .build()).orElse(null);
    }
}
