package com.swiftdrop.auth.admin.api.dto;

import com.swiftdrop.auth.admin.UserView;

import java.util.List;
import java.util.UUID;

public record AdminUserResponse(UUID id, String email, boolean emailVerified, String status, List<String> roles) {

    public static AdminUserResponse from(UserView user) {
        return new AdminUserResponse(user.id(), user.email(), user.emailVerified(), user.status().name(), user.roles());
    }
}
