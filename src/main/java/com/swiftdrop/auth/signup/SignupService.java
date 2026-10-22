package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.Role;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
public class SignupService {

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
    public User signUp(String email, String rawPassword) {
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw new EmailAlreadyUsedException();
        }

        Role customer = roleRepository.findByName(Role.CUSTOMER)
                .orElseThrow(() -> new IllegalStateException("Role missing from database: " + Role.CUSTOMER));

        User user = new User(normalizedEmail, passwordEncoder.encode(rawPassword));
        user.addRole(customer);
        return userRepository.save(user);
    }
}
