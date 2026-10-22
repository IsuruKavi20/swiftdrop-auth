package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.InvalidEmailException;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.SQLException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignupServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private SignupService signupService;

    @BeforeEach
    void setUp() {
        signupService = new SignupService(userRepository, roleRepository, passwordEncoder);
    }

    @Test
    void createsCustomerWithHashedPassword() {
        // Arrange
        Role customer = mock(Role.class);
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(Role.CUSTOMER)).thenReturn(Optional.of(customer));
        when(passwordEncoder.encode("a long passphrase")).thenReturn("$argon2id$hashed");
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(call -> call.getArgument(0));

        // Act
        User user = signupService.signUp("isuru@x.com", "a long passphrase");

        // Assert
        assertThat(user.getEmail()).isEqualTo("isuru@x.com");
        assertThat(user.getPasswordHash()).isEqualTo("$argon2id$hashed");
        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(user.getRoles()).containsExactly(customer);
    }

    @Test
    void rejectsDuplicateEmailWithoutHashingOrSaving() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(true);

        assertThatThrownBy(() -> signupService.signUp("isuru@x.com", "a long passphrase"))
                .isInstanceOf(EmailAlreadyUsedException.class);

        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void storesEmailNormalised() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(Role.CUSTOMER)).thenReturn(Optional.of(mock(Role.class)));
        when(passwordEncoder.encode(anyString())).thenReturn("$argon2id$hashed");
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(call -> call.getArgument(0));

        User user = signupService.signUp("  Ｉsuru@X.com ", "a long passphrase");

        assertThat(user.getEmail()).isEqualTo("isuru@x.com");
    }

    @Test
    void rejectsInvalidEmailBeforeTouchingTheDatabase() {
        assertThatThrownBy(() -> signupService.signUp("not-an-email", "a long passphrase"))
                .isInstanceOf(InvalidEmailException.class);

        verify(userRepository, never()).existsByEmail(anyString());
    }

    @Test
    void duplicateDetectedByDatabaseUniqueConstraintBecomesEmailAlreadyUsed() {
        // Race: both requests passed existsByEmail, the database rejects the second INSERT
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(Role.CUSTOMER)).thenReturn(Optional.of(mock(Role.class)));
        when(passwordEncoder.encode(anyString())).thenReturn("$argon2id$hashed");
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(uniqueViolation("uk_users_email"));

        assertThatThrownBy(() -> signupService.signUp("isuru@x.com", "a long passphrase"))
                .isInstanceOf(EmailAlreadyUsedException.class);
    }

    @Test
    void otherDatabaseConstraintErrorsAreNotHidden() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(Role.CUSTOMER)).thenReturn(Optional.of(mock(Role.class)));
        when(passwordEncoder.encode(anyString())).thenReturn("$argon2id$hashed");
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(uniqueViolation("some_other_constraint"));

        assertThatThrownBy(() -> signupService.signUp("isuru@x.com", "a long passphrase"))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void failsClearlyWhenCustomerRoleIsMissing() {
        when(userRepository.existsByEmail("isuru@x.com")).thenReturn(false);
        when(roleRepository.findByName(Role.CUSTOMER)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> signupService.signUp("isuru@x.com", "a long passphrase"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(Role.CUSTOMER);
    }

    private static DataIntegrityViolationException uniqueViolation(String constraintName) {
        var cause = new ConstraintViolationException(
                "duplicate key", new SQLException("duplicate key", "23505"), constraintName);
        return new DataIntegrityViolationException("could not execute statement", cause);
    }
}
