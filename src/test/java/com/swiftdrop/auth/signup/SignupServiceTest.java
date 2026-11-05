package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.InvalidEmailException;
import com.swiftdrop.auth.user.InvalidPersonNameException;
import com.swiftdrop.auth.user.PersonName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.text.Normalizer;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignupServiceTest {

    private static final String NAME = "Isuru Kavinda";
    private static final String PASSWORD = "a long passphrase here";

    @Mock
    private UserRegistrar registrar;

    @Mock
    private PasswordEncoder passwordEncoder;

    private SignupService signupService;

    @BeforeEach
    void setUp() {
        PasswordPolicy policy = new PasswordPolicy(password -> new CompromisedPasswordDecision(false));
        signupService = new SignupService(policy, passwordEncoder, registrar, new Bulkhead(2, Duration.ZERO));
    }

    @Test
    void newEmailCreatesAccountWithHashedPassword() {
        when(passwordEncoder.encode(PASSWORD)).thenReturn("{argon2}hash");

        SignupOutcome outcome = signupService.signUp(NAME, "  Isuru@X.com ", PASSWORD);

        assertThat(outcome).isEqualTo(SignupOutcome.ACCOUNT_CREATED);
        verify(registrar).registerCustomer(EmailAddress.of("isuru@x.com"), PersonName.of(NAME), "{argon2}hash");
    }

    @Test
    void existingEmailStillHashesThePasswordSoTimingMatches() {
        when(passwordEncoder.encode(PASSWORD)).thenReturn("{argon2}hash");
        doThrow(new DuplicateEmailException()).when(registrar).registerCustomer(any(), any(), anyString());

        SignupOutcome outcome = signupService.signUp(NAME, "isuru@x.com", PASSWORD);

        assertThat(outcome).isEqualTo(SignupOutcome.EMAIL_ALREADY_REGISTERED);
        verify(passwordEncoder).encode(PASSWORD);
        verify(registrar).notifyExistingAccount(EmailAddress.of("isuru@x.com"));
    }

    @Test
    void invalidEmailIsRejectedBeforeAnythingElse() {
        assertThatThrownBy(() -> signupService.signUp(NAME, "not-an-email", PASSWORD))
                .isInstanceOf(InvalidEmailException.class);

        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void invalidNameIsRejectedBeforeThePasswordIsHashed() {
        assertThatThrownBy(() -> signupService.signUp("Isuru\u202Eevil", "isuru@x.com", PASSWORD))
                .isInstanceOf(InvalidPersonNameException.class);

        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void weakPasswordIsRejectedBeforeLookingAtTheAccount() {
        assertThatThrownBy(() -> signupService.signUp(NAME, "isuru@x.com", "short"))
                .isInstanceOf(WeakPasswordException.class);

        verify(registrar, never()).registerCustomer(any(), any(), anyString());
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void theNfcNormalisedPasswordIsWhatGetsHashed() {
        String composed = "café-password-long";
        when(passwordEncoder.encode(composed)).thenReturn("{argon2}hash");

        signupService.signUp(NAME, "isuru@x.com", Normalizer.normalize(composed, Normalizer.Form.NFD));

        verify(passwordEncoder).encode(composed);
    }
}
