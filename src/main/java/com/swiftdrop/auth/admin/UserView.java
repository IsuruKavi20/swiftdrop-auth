package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserStatus;

import java.util.List;
import java.util.UUID;

/** What administration may see of a user: never the password hash or lock/counter internals. */
public record UserView(UUID id, String email, boolean emailVerified, UserStatus status, List<String> roles) {

    static UserView of(User user) {
        List<String> roles = user.getRoles().stream().map(role -> role.getName().name()).sorted().toList();
        return new UserView(user.getId(), user.getEmail(), user.isEmailVerified(), user.getStatus(), roles);
    }
}
