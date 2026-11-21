package com.swiftdrop.auth.account;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    boolean existsByUserIdAndCreatedAtAfter(UUID userId, Instant since);

    long countByUserIdAndCreatedAtAfter(UUID userId, Instant since);

    /**
     * Uses the token in ONE statement: check and update happen atomically in the database, so two
     * simultaneous requests with the same token can't both succeed. Returns 1 if it was usable, else 0.
     */
    @Modifying
    @Query("""
            update PasswordResetToken t set t.consumedAt = :now
            where t.id = :id and t.consumedAt is null and t.expiresAt > :now""")
    int consumeIfUsable(@Param("id") UUID id, @Param("now") Instant now);

    /** Marks every still-open token of the user as used, so only the newest link works. */
    @Modifying
    @Query("update PasswordResetToken t set t.consumedAt = :now where t.userId = :userId and t.consumedAt is null")
    int invalidateOpenTokens(@Param("userId") UUID userId, @Param("now") Instant now);

    @Modifying
    @Query("delete from PasswordResetToken t where t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
