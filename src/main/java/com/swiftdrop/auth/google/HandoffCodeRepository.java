package com.swiftdrop.auth.google;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

interface HandoffCodeRepository extends JpaRepository<HandoffCode, UUID> {

    Optional<HandoffCode> findByCodeHash(String codeHash);

    /** Check and use in ONE statement, so two requests with the same code can't both succeed. 1 = used now. */
    @Modifying
    @Query("""
            update HandoffCode c set c.consumedAt = :now
            where c.id = :id and c.consumedAt is null and c.expiresAt > :now""")
    int consumeIfUsable(@Param("id") UUID id, @Param("now") Instant now);

    @Modifying
    @Query("delete from HandoffCode c where c.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
