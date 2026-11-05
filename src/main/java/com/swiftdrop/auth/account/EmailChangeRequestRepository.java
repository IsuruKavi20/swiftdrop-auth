package com.swiftdrop.auth.account;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

interface EmailChangeRequestRepository extends JpaRepository<EmailChangeRequest, UUID> {

    boolean existsByUserIdAndCreatedAtAfter(UUID userId, Instant after);

    long countByUserIdAndCreatedAtAfter(UUID userId, Instant after);

    Optional<EmailChangeRequest> findByConfirmTokenHash(String confirmTokenHash);

    /** Check-and-use in one atomic UPDATE: a link used twice at the same moment succeeds only once (1 row). */
    @Modifying(flushAutomatically = true)
    @Query("""
            UPDATE EmailChangeRequest r SET r.confirmedAt = :now
            WHERE r.id = :id AND r.confirmedAt IS NULL AND r.cancelledAt IS NULL AND r.confirmExpiresAt > :now""")
    int confirmIfOpen(@Param("id") UUID id, @Param("now") Instant now);

    /** A newer request replaces any open one: only the latest link can ever change the email. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            UPDATE EmailChangeRequest r SET r.cancelledAt = :now
            WHERE r.userId = :userId AND r.confirmedAt IS NULL AND r.cancelledAt IS NULL""")
    int cancelOpen(@Param("userId") UUID userId, @Param("now") Instant now);
}
