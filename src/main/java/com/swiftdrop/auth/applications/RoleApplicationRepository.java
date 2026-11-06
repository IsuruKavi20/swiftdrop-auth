package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.user.RoleName;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface RoleApplicationRepository extends JpaRepository<RoleApplication, UUID> {

    boolean existsByUserIdAndRoleAndStatus(UUID userId, RoleName role, ApplicationStatus status);

    boolean existsByUserIdAndRoleAndStatusAndDecidedAtAfter(UUID userId, RoleName role, ApplicationStatus status,
                                                            Instant after);

    List<RoleApplication> findByUserIdOrderByCreatedAtDesc(UUID userId);

    Optional<RoleApplication> findByIdAndUserId(UUID id, UUID userId);

    /** The approvers' queue: one status, the roles they may decide, oldest first, at most {@code limit}. */
    List<RoleApplication> findByStatusAndRoleInOrderByCreatedAtAsc(ApplicationStatus status,
                                                                   Collection<RoleName> roles, Limit limit);

    /** Only the applicant's id, NOT the entity: nothing gets cached before the row locks are taken. */
    @Query("SELECT a.userId FROM RoleApplication a WHERE a.id = :id")
    Optional<UUID> findUserIdById(@Param("id") UUID id);

    /** Read under a row lock at decision time: two approvers at the same moment can't both decide. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM RoleApplication a WHERE a.id = :id")
    Optional<RoleApplication> lockById(@Param("id") UUID id);
}
