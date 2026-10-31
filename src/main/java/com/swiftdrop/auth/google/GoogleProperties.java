package com.swiftdrop.auth.google;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;

/**
 * {@code swiftdrop.google.*}: the Google Cloud OAuth client, from the environment (GOOGLE_CLIENT_ID,
 * GOOGLE_CLIENT_SECRET). Both missing = Google login switched off (development); prod refuses that.
 * {@code publicBaseUrl} pins the address Google sends users back to, instead of trusting request headers
 * (required in prod, e.g. https://auth.swiftdrop.dev).
 */
@ConfigurationProperties("swiftdrop.google")
public record GoogleProperties(String clientId, String clientSecret, URI publicBaseUrl) {

    public boolean enabled() {
        return clientId != null && !clientId.isBlank() && clientSecret != null && !clientSecret.isBlank();
    }

    @Override
    public String toString() {
        return "GoogleProperties[clientId=" + clientId + ", clientSecret=redacted]";
    }
}
