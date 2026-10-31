package com.swiftdrop.auth.user;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

import java.util.Optional;
import java.util.UUID;

/**
 * Emails are stored already normalised (see {@link EmailAddress}), so plain equality is used:
 * it matches the database's unique constraint and can use its index.
 */
public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);

    /** For login: the user, their roles AND those roles' permissions in one query (all go into the token). */
    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<User> findWithRolesByEmail(String email);

    /** Only the id: lets a caller take the row lock ({@link #lockById}) before reading the user. */
    @Query("select u.id from User u where u.email = :email")
    Optional<UUID> findIdByEmail(@Param("email") String email);

    @Query("SELECT count(u) FROM User u JOIN u.roles r WHERE r.name = :role")
    long countWithRole(@Param("role") RoleName role);

    /**
     * SELECT ... FOR UPDATE on the user row. Lock order everywhere: USER first, then refresh tokens / roles.
     * It serialises login, refresh and role changes of the same user, so a revoke can't miss a new session.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id = :id")
    Optional<User> lockById(@Param("id") UUID id);

    /** For administration and refresh: the user, roles and permissions in one query. */
    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<User> findWithRolesById(UUID id);

    /** Direct UPDATE, no version check: parallel logins of one user must not fail each other. Clears any lock. */
    @Modifying
    @Query("update User u set u.lastLoginAt = :now, u.failedLoginCount = 0, u.lockedUntil = null, "
            + "u.lastFailedLoginAt = null where u.id = :id")
    int updateLastLoginAt(@Param("id") UUID id, @Param("now") Instant now);

    /**
     * One wrong password, counted in ONE statement (parallel guesses can't lose a count). The SET expressions see
     * the OLD values. 5 failures in a row lock for 1 minute, 10 for 5, 15 and more for 15 (deep dive 26).
     * Two limits on abuse: failures DURING a lock are not counted (a stranger can't keep you locked forever by
     * guessing every 15 minutes), and a failure after a quiet hour starts again from 1 (old typos fade away).
     */
    @Modifying
    @Query("""
            update User u set
                u.failedLoginCount = case when u.lastFailedLoginAt is null or u.lastFailedLoginAt < :forgetBefore
                    then 1 else u.failedLoginCount + 1 end,
                u.lockedUntil = case
                    when u.lastFailedLoginAt is null or u.lastFailedLoginAt < :forgetBefore then u.lockedUntil
                    when u.failedLoginCount + 1 >= 15 then :lockLong
                    when u.failedLoginCount + 1 >= 10 then :lockMedium
                    when u.failedLoginCount + 1 >= 5 then :lockShort
                    else u.lockedUntil end,
                u.lastFailedLoginAt = :now
            where u.id = :id and (u.lockedUntil is null or u.lockedUntil <= :now)""")
    int recordFailedLogin(@Param("id") UUID id, @Param("now") Instant now, @Param("forgetBefore") Instant forgetBefore,
                          @Param("lockShort") Instant lockShort, @Param("lockMedium") Instant lockMedium,
                          @Param("lockLong") Instant lockLong);

    /** Compare-and-set: only if the hash is still the one we verified; bumps the version like a normal edit. */
    @Modifying
    @Query("update User u set u.passwordHash = :newHash, u.updatedAt = :now, u.version = u.version + 1 "
            + "where u.id = :id and u.passwordHash = :oldHash")
    int replacePasswordHash(@Param("id") UUID id, @Param("oldHash") String oldHash, @Param("newHash") String newHash,
                            @Param("now") Instant now);
}
