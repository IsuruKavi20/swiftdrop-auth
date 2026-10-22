package com.swiftdrop.auth.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Emails are stored already normalised (see {@link EmailAddress}), so plain equality is used:
 * it matches the database's unique constraint and can use its index.
 */
public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);
}
