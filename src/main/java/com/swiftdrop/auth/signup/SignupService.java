package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import com.swiftdrop.auth.user.EmailAddress;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * The signup use case. Built so a caller cannot tell whether an email was already registered:
 * the same checks run and the password is always hashed, whatever the outcome.
 */
@Service
public class SignupService {

    private final PasswordPolicy passwordPolicy;
    private final PasswordEncoder passwordEncoder;
    private final UserRegistrar registrar;
    private final Bulkhead passwordWork;

    SignupService(PasswordPolicy passwordPolicy, PasswordEncoder passwordEncoder, UserRegistrar registrar,
                  Bulkhead passwordWork) {
        this.passwordPolicy = passwordPolicy;
        this.passwordEncoder = passwordEncoder;
        this.registrar = registrar;
        this.passwordWork = passwordWork;
    }

    public SignupOutcome signUp(String rawEmail, String rawPassword) {
        EmailAddress email = EmailAddress.of(rawEmail);
        // Breach check + Argon2 are the expensive part (network + 64 MB): only a few may run at once
        String passwordHash = passwordWork.call(() -> {
            // Password rules before looking at the account: a weak password is rejected the same way for everyone
            String password = passwordPolicy.validate(rawPassword, email);
            // Always hash, even if the email turns out to exist, so response time doesn't reveal it
            return passwordEncoder.encode(password);
        });
        try {
            registrar.registerCustomer(email, passwordHash);
            return SignupOutcome.ACCOUNT_CREATED;
        } catch (DuplicateEmailException alreadyRegistered) {
            return SignupOutcome.EMAIL_ALREADY_REGISTERED;
        }
    }
}
