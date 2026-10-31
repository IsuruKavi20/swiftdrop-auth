package com.swiftdrop.auth.merchant.api.dto;

import com.swiftdrop.auth.merchant.MerchantClients;

import java.time.Instant;

/** The ONLY response that ever contains the secret: store it now, it can't be shown again. */
public record CreatedClientResponse(String clientId, String clientSecret, String name, Instant createdAt) {

    public static CreatedClientResponse from(MerchantClients.CreatedClient client) {
        return new CreatedClientResponse(client.clientId(), client.clientSecret(), client.name(), client.createdAt());
    }

    @Override
    public String toString() {
        return "CreatedClientResponse[clientId=" + clientId + ", clientSecret=redacted]";
    }
}
