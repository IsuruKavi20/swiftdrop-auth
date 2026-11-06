package com.swiftdrop.auth.user;

import com.swiftdrop.auth.common.privacy.ExportMap;
import com.swiftdrop.auth.common.privacy.PersonalDataExporter;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/** The account and identity profile. The password hash is never exported (only whether a password exists). */
@Component
class UserDataExporter implements PersonalDataExporter {

    private final UserRepository users;

    UserDataExporter(UserRepository users) {
        this.users = users;
    }

    @Override
    public String section() {
        return "account";
    }

    @Override
    @Transactional(readOnly = true)
    public Object export(UUID userId) {
        return users.findWithRolesById(userId).map(user -> ExportMap.of()
                .put("id", user.getId())
                .put("email", user.getEmail())
                .put("email_verified", user.isEmailVerified())
                .put("name", user.getName())
                .put("given_name", user.getGivenName())
                .put("family_name", user.getFamilyName())
                .put("picture", user.getPictureUrl())
                .put("locale", user.getLocale())
                .put("profile_source", user.getProfileSource())
                .put("profile_updated_at", user.getProfileUpdatedAt())
                .put("status", user.getStatus())
                .put("roles", user.roleNames())
                .put("has_password", user.getPasswordHash() != null)
                .put("created_at", user.getCreatedAt())
                .put("last_login_at", user.getLastLoginAt())
                .build()).orElse(null);
    }
}
