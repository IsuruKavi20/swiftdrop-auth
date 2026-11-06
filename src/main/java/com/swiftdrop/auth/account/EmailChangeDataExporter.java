package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.privacy.ExportMap;
import com.swiftdrop.auth.common.privacy.PersonalDataExporter;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/** The history of login email changes. The link token hashes are never exported. */
@Component
class EmailChangeDataExporter implements PersonalDataExporter {

    private final EmailChangeRequestRepository requests;

    EmailChangeDataExporter(EmailChangeRequestRepository requests) {
        this.requests = requests;
    }

    @Override
    public String section() {
        return "email_changes";
    }

    @Override
    @Transactional(readOnly = true)
    public Object export(UUID userId) {
        return requests.findByUserIdOrderByCreatedAtAsc(userId).stream().map(request -> ExportMap.of()
                .put("old_email", request.getOldEmail())
                .put("new_email", request.getNewEmail())
                .put("requested_at", request.getCreatedAt())
                .put("confirmed_at", request.getConfirmedAt())
                .put("undone_at", request.getRevertedAt())
                .put("cancelled_at", request.getCancelledAt())
                .build()).toList();
    }
}
