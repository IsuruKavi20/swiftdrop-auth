package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.sql.SQLException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserRegistrarTest {

    private static final EmailAddress EMAIL = EmailAddress.of("isuru@x.com");
    private static final String HASH = "{argon2}$argon2id$hashed";

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    private UserRegistrar registrar;

    @BeforeEach
    void setUp() {
        registrar = new UserRegistrar(userRepository, roleRepository);
    }

    @Test
    void savesUnverifiedActiveCustomerWithTheGivenHash() {
        Role customer = mock(Role.class);
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(customer));
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(call -> call.getArgument(0));

        registrar.registerCustomer(EMAIL, HASH);

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getEmail()).isEqualTo("isuru@x.com");
        assertThat(saved.getValue().getPasswordHash()).isEqualTo(HASH);
        assertThat(saved.getValue().getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(saved.getValue().isEmailVerified()).isFalse();
        assertThat(saved.getValue().getRoles()).containsExactly(customer);
    }

    @Test
    void existingEmailIsReportedWithoutSaving() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(true);

        assertThatThrownBy(() -> registrar.registerCustomer(EMAIL, HASH))
                .isInstanceOf(DuplicateEmailException.class);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void uniqueConstraintViolationFromConcurrentSignupIsReportedAsDuplicate() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(mock(Role.class)));
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(uniqueViolation("uk_users_email"));

        assertThatThrownBy(() -> registrar.registerCustomer(EMAIL, HASH))
                .isInstanceOf(DuplicateEmailException.class);
    }

    @Test
    void otherDatabaseConstraintErrorsAreNotHidden() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(mock(Role.class)));
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(uniqueViolation("some_other_constraint"));

        assertThatThrownBy(() -> registrar.registerCustomer(EMAIL, HASH))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void failsClearlyWhenCustomerRoleIsMissing() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> registrar.registerCustomer(EMAIL, HASH))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(RoleName.CUSTOMER.name());
    }

    private static DataIntegrityViolationException uniqueViolation(String constraintName) {
        var cause = new ConstraintViolationException(
                "duplicate key", new SQLException("duplicate key", "23505"), constraintName);
        return new DataIntegrityViolationException("could not execute statement", cause);
    }
}
