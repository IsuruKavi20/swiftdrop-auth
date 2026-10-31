package com.swiftdrop.auth.merchant;

import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface MerchantRepository extends JpaRepository<Merchant, UUID> {

    Optional<Merchant> findByUserId(UUID userId);

    /** Only the owner's id (no entity in Hibernate's cache), so the caller can lock the USER row first. */
    @Query("select m.userId from Merchant m where m.id = :id")
    Optional<UUID> findUserIdById(@Param("id") UUID id);

    /** SELECT ... FOR UPDATE: two admins deciding at once queue here; the second sees the first's decision. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select m from Merchant m where m.id = :id")
    Optional<Merchant> lockById(@Param("id") UUID id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select m from Merchant m where m.userId = :userId")
    Optional<Merchant> lockByUserId(@Param("userId") UUID userId);

    List<Merchant> findByStatusOrderByCreatedAtAsc(MerchantStatus status, Limit limit);

    boolean existsByRegistrationNumberAndStatusInAndIdNot(String registrationNumber, List<MerchantStatus> statuses,
                                                         UUID id);
}
