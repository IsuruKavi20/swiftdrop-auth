package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.InvalidEmailException;
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

        SignupOutcome outcome = signupService.signUp("  Isuru@X.com ", PASSWORD);

        assertThat(outcome).isEqualTo(SignupOutcome.ACCOUNT_CREATED);
        verify(registrar).registerCustomer(EmailAddress.of("isuru@x.com"), "{argon2}hash");
    }

    @Test
    void existingEmailStillHashesThePasswordSoTimingMatches() {
        when(passwordEncoder.encode(PASSWORD)).thenReturn("{argon2}hash");
        doThrow(new DuplicateEmailException()).when(registrar).registerCustomer(any(), anyString());

        SignupOutcome outcome = signupService.signUp("isuru@x.com", PASSWORD);

        assertThat(outcome).isEqualTo(SignupOutcome.EMAIL_ALREADY_REGISTERED);
        verify(passwordEncoder).encode(PASSWORD);
    }

    @Test
    void invalidEmailIsRejectedBeforeAnythingElse() {
        assertThatThrownBy(() -> signupService.signUp("not-an-email", PASSWORD))
                .isInstanceOf(InvalidEmailException.class);

        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void weakPasswordIsRejectedBeforeLookingAtTheAccount() {
        assertThatThrownBy(() -> signupService.signUp("isuru@x.com", "short"))
                .isInstanceOf(WeakPasswordException.class);

        verify(registrar, never()).registerCustomer(any(), anyString());
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void theNfcNormalisedPasswordIsWhatGetsHashed() {
        String composed = "café-password-long";
        when(passwordEncoder.encode(composed)).thenReturn("{argon2}hash");

        signupService.signUp("isuru@x.com", Normalizer.normalize(composed, Normalizer.Form.NFD));

        verify(passwordEncoder).encode(composed);
    }
}
