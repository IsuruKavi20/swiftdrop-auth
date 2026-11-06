package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.privacy.PersonalDataExporter;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * "Download my data" (identity step 3d; GDPR Art. 15/20, Sri Lanka PDPA No. 9 of 2022): collects every module's
 * section through {@link PersonalDataExporter}. Only the auth service's data; SwiftDrop exports its own part.
 */
@Service
public class PersonalDataExport {

    private final List<PersonalDataExporter> exporters;
    private final UserRepository users;
    private final Clock clock;

    PersonalDataExport(List<PersonalDataExporter> exporters, UserRepository users, Clock clock) {
        this.exporters = exporters.stream().sorted(Comparator.comparing(PersonalDataExporter::section)).toList();
        this.users = users;
        this.clock = clock;
    }

    /** One read-only transaction: every section comes from the same consistent snapshot. */
    @Transactional(readOnly = true)
    public Map<String, Object> of(UUID userId) {
        if (users.findById(userId).filter(User::isUsable).isEmpty()) {
            throw new BadCredentialsException("Account not active");
        }
        Map<String, Object> sections = new LinkedHashMap<>();
        for (PersonalDataExporter exporter : exporters) {
            sections.put(exporter.section(), exporter.export(userId));
        }
        Map<String, Object> export = new LinkedHashMap<>();
        export.put("service", "swiftdrop-auth");
        export.put("subject", userId);
        export.put("exported_at", clock.instant());
        export.put("sections", sections);
        return export;
    }
}
