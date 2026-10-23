package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * The database part of signup, in its own short transaction. Slow work (password hashing,
 * the breach check over the network) happens before, so no DB connection is held during it.
 */
@Component
class UserRegistrar {

    private static final String UNIQUE_EMAIL_CONSTRAINT = "uk_users_email";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    UserRegistrar(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    /** @throws DuplicateEmailException if the address is already registered (also under a concurrent race) */
    @Transactional
    public void registerCustomer(EmailAddress email, String passwordHash) {
        if (userRepository.existsByEmail(email.value())) {
            throw new DuplicateEmailException();
        }
        Role customer = roleRepository.findByName(RoleName.CUSTOMER)
                .orElseThrow(() -> new IllegalStateException("Role missing from database: " + RoleName.CUSTOMER));

        User user = new User(email, passwordHash);
        user.addRole(customer);
        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            // The existsByEmail check can race with a concurrent signup; the unique constraint is the real guard
            if (e.getCause() instanceof ConstraintViolationException violation
                    && UNIQUE_EMAIL_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName())) {
                throw new DuplicateEmailException();
            }
            throw e;
        }
    }
}
