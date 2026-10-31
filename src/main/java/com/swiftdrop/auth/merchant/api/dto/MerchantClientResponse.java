package com.swiftdrop.auth.merchant.api.dto;

import com.swiftdrop.auth.merchant.MerchantClients;

import java.time.Instant;

/** A client as listed later: never the secret. */
public record MerchantClientResponse(String clientId, String name, Instant createdAt, Instant lastUsedAt) {

    public static MerchantClientResponse from(MerchantClients.ClientView client) {
        return new MerchantClientResponse(client.clientId(), client.name(), client.createdAt(), client.lastUsedAt());
    }
}
