package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeanUtils;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The first admin comes from configuration; only a verified account may receive it. */
class AdminBootstrapTest {

    private final UserRepository users = mock(UserRepository.class);
    private final RoleRepository roles = mock(RoleRepository.class);
    private final Role admin = role(RoleName.ADMIN);

    @Test
    void verifiedUserFromConfigBecomesAdmin() {
        User user = user(true);
        when(users.findWithRolesByEmail("boss@example.com")).thenReturn(Optional.of(user));
        when(roles.findByName(RoleName.ADMIN)).thenReturn(Optional.of(admin));

        new AdminBootstrap(users, roles, "Boss@Example.com").grantConfiguredAdmin();

        assertThat(user.getRoles()).contains(admin);
    }

    @Test
    void unverifiedUserIsNotPromoted() {
        User user = user(false);
        when(users.findWithRolesByEmail("boss@example.com")).thenReturn(Optional.of(user));

        new AdminBootstrap(users, roles, "boss@example.com").grantConfiguredAdmin();

        assertThat(user.getRoles()).doesNotContain(admin);
    }

    @Test
    void nothingConfiguredMeansNothingHappens() {
        new AdminBootstrap(users, roles, "").grantConfiguredAdmin();

        verify(users, never()).findWithRolesByEmail(anyString());
    }

    @Test
    void missingAccountIsOnlyLogged() {
        when(users.findWithRolesByEmail("boss@example.com")).thenReturn(Optional.empty());

        new AdminBootstrap(users, roles, "boss@example.com").grantConfiguredAdmin();

        verify(roles, never()).findByName(RoleName.ADMIN);
    }

    private static User user(boolean verified) {
        User user = new User(EmailAddress.of("boss@example.com"), "{argon2}hash");
        user.addRole(role(RoleName.CUSTOMER));
        if (verified) {
            user.markEmailVerified();
        }
        return user;
    }

    private static Role role(RoleName name) {
        Role role = BeanUtils.instantiateClass(Role.class);
        ReflectionTestUtils.setField(role, "name", name);
        return role;
    }
}
