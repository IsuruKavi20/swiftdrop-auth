package com.swiftdrop.auth.google;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Production must offer Google login (the brief requires it), with the callback address pinned to https:
 * no Google client or no public https address, no startup.
 */
@Component
@Profile("prod")
class GoogleLoginSafetyCheck implements InitializingBean {

    private final GoogleProperties google;

    GoogleLoginSafetyCheck(GoogleProperties google) {
        this.google = google;
    }

    @Override
    public void afterPropertiesSet() {
        if (!google.enabled()) {
            throw new IllegalStateException(
                    "Google login is required in production: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET");
        }
        if (google.publicBaseUrl() == null || !"https".equals(google.publicBaseUrl().getScheme())) {
            throw new IllegalStateException(
                    "Production must pin Google's redirect address: set SWIFTDROP_PUBLIC_BASE_URL to the https URL");
        }
    }
}
