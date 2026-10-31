package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Solves "who makes the first admin?": on startup, the account named in
 * {@code swiftdrop.bootstrap.admin-email} becomes ADMIN, but only if it exists and its email is verified
 * (so nobody can claim admin by signing up with that address first). Idempotent; blank = off.
 * Runs at EVERY start: remove the property once the first admin exists, or a deliberate revoke is undone.
 */
@Component
public class AdminBootstrap {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final UserRepository users;
    private final RoleRepository roles;
    private final String adminEmail;

    public AdminBootstrap(UserRepository users, RoleRepository roles,
                          @Value("${swiftdrop.bootstrap.admin-email:}") String adminEmail) {
        this.users = users;
        this.roles = roles;
        this.adminEmail = adminEmail;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void grantConfiguredAdmin() {
        if (adminEmail == null || adminEmail.isBlank()) {
            return;
        }
        Optional<User> account = users.findWithRolesByEmail(EmailAddress.of(adminEmail).value());
        if (account.isEmpty()) {
            log.warn("Bootstrap admin: configured account does not exist yet; sign up and verify, then restart");
            return;
        }
        User user = account.get();
        if (!user.isEmailVerified() || user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Bootstrap admin: configured account is not verified or not active; ADMIN not granted");
            return;
        }
        if (!user.hasRole(RoleName.ADMIN)) {
            user.addRole(roles.findByName(RoleName.ADMIN).orElseThrow());
            log.info("Bootstrap admin: ADMIN granted to user={}", user.getId());
        }
    }
}
