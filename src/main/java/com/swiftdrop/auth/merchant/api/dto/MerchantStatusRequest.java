package com.swiftdrop.auth.merchant.api.dto;

import com.swiftdrop.auth.merchant.MerchantApplications;
import jakarta.validation.constraints.NotNull;

public record MerchantStatusRequest(@NotNull MerchantApplications.StatusChange change) {
}
