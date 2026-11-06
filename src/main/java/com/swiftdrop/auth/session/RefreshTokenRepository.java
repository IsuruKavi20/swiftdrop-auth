package com.swiftdrop.auth.session;

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

interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * SELECT ... FOR UPDATE: a second refresh with the same token waits here until the first commits,
     * then sees it as used (reuse). So two parallel refreshes can never both succeed.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from RefreshToken t where t.tokenHash = :hash")
    Optional<RefreshToken> lockByHash(@Param("hash") String hash);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /** The live token of each open session (one per family): for "my sessions" and the data export. */
    @Query("""
            select t from RefreshToken t where t.userId = :userId and t.usedAt is null and t.revokedAt is null
            and t.expiresAt > :now order by t.createdAt""")
    List<RefreshToken> findOpenSessions(@Param("userId") UUID userId, @Param("now") Instant now);

    /**
     * Only the owner's id, NOT the entity: a loaded entity would sit in Hibernate's cache, and the later
     * locked query would hand back that stale copy instead of the row as it is after the lock.
     */
    @Query("select t.userId from RefreshToken t where t.tokenHash = :hash")
    Optional<UUID> findUserIdByHash(@Param("hash") String hash);

    @Modifying
    @Query("""
            update RefreshToken t set t.revokedAt = :now, t.revokeReason = :reason
            where t.familyId = :familyId and t.revokedAt is null""")
    int revokeFamily(@Param("familyId") UUID familyId, @Param("reason") RevokeReason reason, @Param("now") Instant now);

    @Modifying
    @Query("""
            update RefreshToken t set t.revokedAt = :now, t.revokeReason = :reason
            where t.userId = :userId and t.revokedAt is null""")
    int revokeAllForUser(@Param("userId") UUID userId, @Param("reason") RevokeReason reason, @Param("now") Instant now);

    /** Deletes only whole dead sessions: used tokens of a live session must stay, to recognise their reuse. */
    @Modifying
    @Query("delete from RefreshToken t where t.familyExpiresAt < :cutoff")
    int deleteSessionsEndedBefore(@Param("cutoff") Instant cutoff);
}
