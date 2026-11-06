package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.privacy.ExportMap;
import com.swiftdrop.auth.common.privacy.PersonalDataExporter;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/** Which outside logins (Google) are linked to the account, and since when. */
@Component
class LinkedLoginDataExporter implements PersonalDataExporter {

    private final OAuthAccountRepository accounts;

    LinkedLoginDataExporter(OAuthAccountRepository accounts) {
        this.accounts = accounts;
    }

    @Override
    public String section() {
        return "linked_logins";
    }

    @Override
    @Transactional(readOnly = true)
    public Object export(UUID userId) {
        return accounts.findByUserId(userId).stream().map(account -> ExportMap.of()
                .put("provider", account.getProvider())
                .put("provider_user_id", account.getProviderUserId())
                .put("linked_at", account.getCreatedAt())
                .build()).toList();
    }
}
