package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.BeanUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.text.Normalizer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-26T10:00:00Z");
    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final String HASH = "{argon2}$argon2id$user-hash";
    private static final String DUMMY = "{argon2}$argon2id$dummy-hash";
    private static final UUID USER_ID = UUID.randomUUID();
    private static final IssuedToken TOKEN = new IssuedToken("signed.jwt.value", Duration.ofMinutes(15));

    @Mock
    private UserRepository users;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private AccessTokenIssuer tokens;

    @Mock
    private LoginRecorder recorder;

    private LoginService service;

    @BeforeEach
    void setUp() {
        when(encoder.encode(anyString())).thenReturn(DUMMY);   // the dummy hash made at startup
        service = new LoginService(users, encoder, tokens, recorder, new Bulkhead(2, Duration.ZERO),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void correctPasswordForVerifiedActiveUserGetsAToken() {
        User user = user(true, UserStatus.ACTIVE);
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user));
        when(encoder.matches(PASSWORD, HASH)).thenReturn(true);
        when(tokens.issue(USER_ID, List.of("CUSTOMER"))).thenReturn(TOKEN);

        IssuedToken token = service.login("  Isuru@X.com ", PASSWORD);

        assertThat(token).isEqualTo(TOKEN);
        verify(recorder).recordSuccessfulLogin(USER_ID, NOW, HASH, null);
    }

    @Test
    void unknownEmailStillRunsAFullPasswordCheckAgainstTheDummyHash() {
        when(users.findWithRolesByEmail("nobody@x.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login("nobody@x.com", PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(encoder).matches(PASSWORD, DUMMY);   // same Argon2 cost as a real user: no timing difference
    }

    @Test
    void malformedEmailGetsTheSameAnswerAndTheSameWork() {
        when(users.findWithRolesByEmail(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login("not-an-email", PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(users).findWithRolesByEmail(anyString());   // a lookup still happens: same timing
        verify(encoder).matches(PASSWORD, DUMMY);
    }

    @Test
    void unreadableStoredHashIsAPlainMismatchNotAServerError() {
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user(true, UserStatus.ACTIVE)));
        when(encoder.matches(PASSWORD, HASH)).thenThrow(new IllegalArgumentException("no encoder for id"));

        assertThatThrownBy(() -> service.login("isuru@x.com", PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(encoder).matches(PASSWORD, DUMMY);
    }

    @Test
    void wrongPasswordIsRejected() {
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user(true, UserStatus.ACTIVE)));
        when(encoder.matches(PASSWORD, HASH)).thenReturn(false);

        assertThatThrownBy(() -> service.login("isuru@x.com", PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(tokens, never()).issue(any(), any());
    }

    @Test
    void lockedOrDisabledAccountsLookExactlyLikeAWrongPassword() {
        for (UserStatus hidden : new UserStatus[] {UserStatus.LOCKED, UserStatus.DISABLED}) {
            when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user(true, hidden)));
            when(encoder.matches(PASSWORD, HASH)).thenReturn(true);

            assertThatThrownBy(() -> service.login("isuru@x.com", PASSWORD))
                    .isInstanceOf(InvalidCredentialsException.class);
        }
        verify(tokens, never()).issue(any(), any());
    }

    @Test
    void temporaryLockStillRunningIsHiddenToo() {
        User user = user(true, UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user, "lockedUntil", NOW.plusSeconds(30));
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user));
        when(encoder.matches(PASSWORD, HASH)).thenReturn(true);

        assertThatThrownBy(() -> service.login("isuru@x.com", PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void unverifiedEmailIsOnlyRevealedAfterTheCorrectPassword() {
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user(false, UserStatus.ACTIVE)));
        when(encoder.matches(PASSWORD, HASH)).thenReturn(true);

        assertThatThrownBy(() -> service.login("isuru@x.com", PASSWORD))
                .isInstanceOf(EmailNotVerifiedException.class);
    }

    @Test
    void unverifiedEmailWithWrongPasswordGetsTheGenericAnswer() {
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user(false, UserStatus.ACTIVE)));
        when(encoder.matches(PASSWORD, HASH)).thenReturn(false);

        assertThatThrownBy(() -> service.login("isuru@x.com", PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void googleOnlyAccountWithoutPasswordCannotLogInWithAPassword() {
        User googleOnly = user(true, UserStatus.ACTIVE);
        ReflectionTestUtils.setField(googleOnly, "passwordHash", null);
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(googleOnly));
        when(encoder.matches(PASSWORD, DUMMY)).thenReturn(true);

        assertThatThrownBy(() -> service.login("isuru@x.com", PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void hashFromOlderSettingsIsReplacedAfterASuccessfulLogin() {
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user(true, UserStatus.ACTIVE)));
        when(encoder.matches(PASSWORD, HASH)).thenReturn(true);
        when(encoder.upgradeEncoding(HASH)).thenReturn(true);
        when(encoder.encode(PASSWORD)).thenReturn("{argon2}$argon2id$stronger");
        when(tokens.issue(eq(USER_ID), any())).thenReturn(TOKEN);

        service.login("isuru@x.com", PASSWORD);

        verify(recorder).recordSuccessfulLogin(USER_ID, NOW, HASH, "{argon2}$argon2id$stronger");
    }

    @Test
    void passwordIsComparedInTheSameNormalisedFormSignupHashed() {
        String composed = "café-password-long";
        when(users.findWithRolesByEmail("isuru@x.com")).thenReturn(Optional.of(user(true, UserStatus.ACTIVE)));
        when(encoder.matches(composed, HASH)).thenReturn(true);
        when(tokens.issue(eq(USER_ID), any())).thenReturn(TOKEN);

        service.login("isuru@x.com", Normalizer.normalize(composed, Normalizer.Form.NFD));

        verify(encoder).matches(composed, HASH);
    }

    private static User user(boolean verified, UserStatus status) {
        User user = new User(EmailAddress.of("isuru@x.com"), HASH);
        ReflectionTestUtils.setField(user, "id", USER_ID);
        ReflectionTestUtils.setField(user, "status", status);
        // A real Role (not a mock): this helper runs inside when(...), where Mockito forbids nested stubbing
        Role customer = BeanUtils.instantiateClass(Role.class);
        ReflectionTestUtils.setField(customer, "name", RoleName.CUSTOMER);
        user.addRole(customer);
        if (verified) {
            user.markEmailVerified();
        }
        return user;
    }
}
