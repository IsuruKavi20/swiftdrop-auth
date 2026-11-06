package com.swiftdrop.auth.account;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface EmailChangeRequestRepository extends JpaRepository<EmailChangeRequest, UUID> {

    boolean existsByUserIdAndCreatedAtAfter(UUID userId, Instant after);

    long countByUserIdAndCreatedAtAfter(UUID userId, Instant after);

    /**
     * Read under a row lock for the background email jobs. Without it, a job holding an old copy would write the
     * whole row back and undo a cancel made meanwhile (lost update: a cancelled link would work again).
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT r FROM EmailChangeRequest r WHERE r.id = :id")
    Optional<EmailChangeRequest> lockById(@Param("id") UUID id);

    Optional<EmailChangeRequest> findByConfirmTokenHash(String confirmTokenHash);

    List<EmailChangeRequest> findByUserIdOrderByCreatedAtAsc(UUID userId);

    /** Account deletion erases the history: old/new addresses and every undo/confirm link hash. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from EmailChangeRequest r where r.userId = :userId")
    int deleteByUserId(@Param("userId") UUID userId);

    Optional<EmailChangeRequest> findByRevertTokenHash(String revertTokenHash);

    /** The undo link: single use, only after confirmation, within its 7 days. */
    @Modifying(flushAutomatically = true)
    @Query("""
            UPDATE EmailChangeRequest r SET r.revertedAt = :now
            WHERE r.id = :id AND r.revertedAt IS NULL AND r.confirmedAt IS NOT NULL AND r.revertExpiresAt > :now""")
    int revertIfOpen(@Param("id") UUID id, @Param("now") Instant now);

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
