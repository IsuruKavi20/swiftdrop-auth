package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SignupService {

    private static final String UNIQUE_EMAIL_CONSTRAINT = "uk_users_email";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public SignupService(UserRepository userRepository,
                         RoleRepository roleRepository,
                         PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public SignupResult signUp(String rawEmail, String rawPassword) {
        EmailAddress email = EmailAddress.of(rawEmail);

        if (userRepository.existsByEmail(email.value())) {
            throw new EmailAlreadyUsedException();
        }

        Role customer = roleRepository.findByName(RoleName.CUSTOMER)
                .orElseThrow(() -> new IllegalStateException("Role missing from database: " + RoleName.CUSTOMER));

        User user = new User(email, passwordEncoder.encode(rawPassword));
        user.addRole(customer);
        return new SignupResult(saveRejectingDuplicateEmail(user).getId());
    }

    // The existsByEmail check can race with a concurrent signup; the unique constraint is the real guard.
    private User saveRejectingDuplicateEmail(User user) {
        try {
            return userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            if (isUniqueEmailViolation(e)) {
                throw new EmailAlreadyUsedException();
            }
            throw e;
        }
    }

    private static boolean isUniqueEmailViolation(DataIntegrityViolationException e) {
        return e.getCause() instanceof ConstraintViolationException violation
                && UNIQUE_EMAIL_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName());
    }
}
