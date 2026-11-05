package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PersonName;
import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;

/**
 * The database part of signup, in its own short transaction. Slow work (password hashing,
 * the breach check over the network) happens before, so no DB connection is held during it.
 */
@Component
class UserRegistrar {

    private static final String UNIQUE_EMAIL_CONSTRAINT = "uk_users_email";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    UserRegistrar(UserRepository userRepository, RoleRepository roleRepository, ApplicationEventPublisher events,
                  Clock clock) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.events = events;
        this.clock = clock;
    }

    /** @throws DuplicateEmailException if the address is already registered (also under a concurrent race) */
    @Transactional
    public void registerCustomer(EmailAddress email, PersonName name, String passwordHash) {
        if (userRepository.existsByEmail(email.value())) {
            throw new DuplicateEmailException();
        }
        Role customer = roleRepository.findByName(RoleName.CUSTOMER)
                .orElseThrow(() -> new IllegalStateException("Role missing from database: " + RoleName.CUSTOMER));

        User user = new User(email, passwordHash);
        // The name the user typed is their own profile: a later Google login won't overwrite it
        user.setOwnProfile(IdentityProfile.ofName(name), clock.instant());
        user.addRole(customer);
        try {
            User saved = userRepository.saveAndFlush(user);
            // Stored in the outbox in THIS transaction: the verification email can't be lost
            events.publishEvent(new AccountRegistered(saved.getId()));
        } catch (DataIntegrityViolationException e) {
            // The existsByEmail check can race with a concurrent signup; the unique constraint is the real guard
            if (e.getCause() instanceof ConstraintViolationException violation
                    && UNIQUE_EMAIL_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName())) {
                throw new DuplicateEmailException();
            }
            throw e;
        }
    }

    /** Lets the owner of an existing account know (by email) that someone tried to sign up with it. */
    @Transactional
    public void notifyExistingAccount(EmailAddress email) {
        userRepository.findByEmail(email.value())
                .ifPresent(existing -> events.publishEvent(new SignupAttemptOnExistingAccount(existing.getId())));
    }
}
